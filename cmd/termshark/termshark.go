// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blang/semver"
	"github.com/fsnotify/fsnotify"
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/capinfo"
	"github.com/gcla/termshark/v2/cli"
	"github.com/gcla/termshark/v2/convs"
	"github.com/gcla/termshark/v2/pcap"
	"github.com/gcla/termshark/v2/streams"
	"github.com/gcla/termshark/v2/system"
	"github.com/gcla/termshark/v2/tty"
	"github.com/gcla/termshark/v2/ui"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gdamore/tcell"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"net/http"
	_ "net/http"
	_ "net/http/pprof"
)

//======================================================================

// Run cmain() and afterwards make sure all goroutines stop, then exit with
// the correct exit code. Go's main() prototype does not provide for returning
// a value.
func main() {
	// TODO - fix this later. goroutinewg is used every time a
	// goroutine is started, to ensure we don't terminate until all are
	// stopped. Any exception is a bug.
	var ensureGoroutinesStopWG sync.WaitGroup
	filter.Goroutinewg = &ensureGoroutinesStopWG
	termshark.Goroutinewg = &ensureGoroutinesStopWG
	pcap.Goroutinewg = &ensureGoroutinesStopWG
	streams.Goroutinewg = &ensureGoroutinesStopWG
	capinfo.Goroutinewg = &ensureGoroutinesStopWG
	convs.Goroutinewg = &ensureGoroutinesStopWG
	ui.Goroutinewg = &ensureGoroutinesStopWG

	res := cmain()
	ensureGoroutinesStopWG.Wait()
	os.Exit(res)
}

func cmain() int {
	startedSuccessfully := false // true if we reached the point where packets were received and the UI started.
	uiSuspended := false         // true if the UI was suspended due to SIGTSTP

	sigChan := make(chan os.Signal, 100)
	// SIGINT and SIGQUIT will arrive only via an external kill command,
	// not the keyboard, because our line discipline is set up to pass
	// ctrl-c and ctrl-\ to termshark as keypress events. But we slightly
	// modify tcell's default and set up ctrl-z to invoke signal SIGTSTP
	// on the foreground process group. An alternative would just be to
	// recognize ctrl-z in termshark and issue a SIGSTOP to getpid() from
	// termshark but this wouldn't stop other processes in a termshark
	// pipeline e.g.
	//
	// tcpdump -i eth0 -w - | termshark -i -
	//
	// sending SIGSTOP to getpid() would not stop tcpdump. The expectation
	// with bash job control is that all processes in the foreground
	// process group will be suspended. I could send SIGSTOP to 0, to try
	// to get all processes in the group, but if e.g. tcpdump is running
	// as root and termshark is not, tcpdump will not be suspended. If
	// instead I set the line discipline such that ctrl-z is not passed
	// through but maps to SIGTSTP, then tcpdump will be stopped by ctrl-z
	// via the shell by virtue of the fact that when all pipeline
	// processes start running, they use the same tty line discipline.
	system.RegisterForSignals(sigChan)

	viper.SetConfigName("termshark") // no need to include file extension - looks for file called termshark.ini for example

	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Cache)
	if err := dirs[0].CreateParentDir("dummy"); err != nil {
		fmt.Printf("Warning: could not create cache dir: %v\n", err)
	}
	dirs = stdConf.QueryFolders(configdir.Global)
	if err := dirs[0].CreateParentDir("dummy"); err != nil {
		fmt.Printf("Warning: could not create config dir: %v\n", err)
	}
	viper.AddConfigPath(dirs[0].Path)

	if f, err := os.OpenFile(filepath.Join(dirs[0].Path, "termshark.toml"), os.O_RDONLY|os.O_CREATE, 0666); err != nil {
		fmt.Printf("Warning: could not create initial config file: %v\n", err)
	} else {
		f.Close()
	}

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Config file not found...")
	}

	if os.Getenv("TERMSHARK_CAPTURE_MODE") == "1" {
		err = system.DumpcapExt(termshark.DumpcapBin(), termshark.TSharkBin(), os.Args[1:]...)
		if err != nil {
			return 1
		} else {
			return 0
		}
	}

	// Used to determine if we should run tshark instead e.g. stdout is not a tty
	var tsopts cli.Tshark

	// Add help flag. This is no use for the user and we don't want to display
	// help for this dummy set of flags designed to check for pass-thru to tshark - but
	// if help is on, then we'll detect it, parse the flags as termshark, then
	// display the intended help.
	tsFlags := flags.NewParser(&tsopts, flags.IgnoreUnknown|flags.HelpFlag)
	_, err = tsFlags.ParseArgs(os.Args)

	passthru := true

	if err != nil {
		// If it's because of --help, then skip the tty check, and display termshark's help. This
		// ensures we don't display a useless help, and further that you can pipe termshark's help
		// into PAGER without invoking tshark.
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			passthru = false
		} else {
			return 1
		}
	}

	if tsopts.TailFileValue() != "" {
		err = termshark.TailFile(tsopts.TailFileValue())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)
			return 1
		} else {
			return 0
		}
	}

	// Run after accessing the config so I can use the configured tshark binary, if there is one. I need that
	// binary in the case that termshark is run where stdout is not a tty, in which case I exec tshark - but
	// it makes sense to use the one in termshark.toml
	if passthru &&
		(cli.FlagIsTrue(tsopts.PassThru) ||
			(tsopts.PassThru == "auto" && !isatty.IsTerminal(os.Stdout.Fd())) ||
			tsopts.PrintIfaces) {

		tsharkBin, kverr := termshark.TSharkPath()
		if kverr != nil {
			fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
			return 1
		}

		args := []string{}
		for _, arg := range os.Args[1:] {
			if !termshark.StringInSlice(arg, cli.TermsharkOnly) && !termshark.StringIsArgPrefixOf(arg, cli.TermsharkOnly) {
				args = append(args, arg)
			}
		}
		args = append([]string{tsharkBin}, args...)

		if runtime.GOOS != "windows" {
			err = syscall.Exec(tsharkBin, args, os.Environ())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error execing tshark binary: %v\n", err)
				return 1
			}
		} else {
			// No exec() on windows
			c := exec.Command(args[0], args[1:]...)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err = c.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error starting tshark: %v\n", err)
				return 1
			}

			err = c.Wait()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error waiting for tshark: %v\n", err)
				return 1
			}

			return 0
		}
	}

	// Termshark's own command line arguments. Used if we don't pass through to tshark.
	var opts cli.Termshark

	// Parse the args now as intended for termshark
	tmFlags := flags.NewParser(&opts, flags.PassDoubleDash)
	var filterArgs []string
	filterArgs, err = tmFlags.Parse()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Command-line error: %v\n\n", err)
		ui.WriteHelp(tmFlags, os.Stderr)
		return 1
	}

	if opts.Help {
		ui.WriteHelp(tmFlags, os.Stdout)
		return 0
	}

	if len(opts.Version) > 0 {
		res := 0
		ui.WriteVersion(tmFlags, os.Stdout)
		if len(opts.Version) > 1 {
			if tsharkBin, kverr := termshark.TSharkPath(); kverr != nil {
				fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
				res = 1
			} else {
				if ver, err := termshark.TSharkVersion(tsharkBin); err != nil {
					fmt.Fprintf(os.Stderr, "Could not determine version of tshark from binary %s\n", tsharkBin)
					res = 1
				} else {
					ui.WriteTsharkVersion(tmFlags, tsharkBin, ver, os.Stdout)
				}
			}
		}
		return res
	}

	usetty := opts.TtyValue()
	if usetty != "" {
		if ttyf, err := os.Open(usetty); err != nil {
			fmt.Fprintf(os.Stderr, "Could not open terminal %s: %v.\n", usetty, err)
			return 1
		} else {
			if !isatty.IsTerminal(ttyf.Fd()) {
				fmt.Fprintf(os.Stderr, "%s is not a terminal.\n", usetty)
				ttyf.Close()
				return 1
			}
			ttyf.Close()
		}
	} else {
		// Always override - in case the user has GOWID_TTY in a shell script (if they're
		// using the gcla fork of tcell for another application).
		usetty = "/dev/tty"
	}
	os.Setenv("GOWID_TTY", usetty)

	// Allow the user to override the shell's TERM variable this way. Perhaps the user runs
	// under screen/tmux, and the TERM variable doesn't reflect the fact their preferred
	// terminal emumlator supports 256 colors.
	termVar := termshark.ConfString("main.term", "")
	if termVar != "" {
		os.Setenv("TERM", termVar)
	}

	var psrcs []pcap.IPacketSource

	defer func() {
		for _, psrc := range psrcs {
			if psrc != nil {
				if remover, ok := psrc.(pcap.ISourceRemover); ok {
					remover.Remove()
				}
			}
		}
	}()

	pcapf := string(opts.Pcap)

	// If no interface specified, and no pcap specified via -r, then we assume the first
	// argument is a pcap file e.g. termshark foo.pcap
	if pcapf == "" && len(opts.Ifaces) == 0 {
		pcapf = string(opts.Args.FilterOrPcap)
		// `termshark` => `termshark -i 1` (livecapture on default interface if no args)
		if pcapf == "" {
			if termshark.IsTerminal(os.Stdin.Fd()) {
				pfile, err := system.PickFile()
				switch err {
				case nil:
					// We're on termux/android, and we were given a file. Note that termux
					// makes a copy, so we ought to clean that up when termshark terminates.
					psrcs = append(psrcs, pcap.TemporaryFileSource{pcap.FileSource{Filename: pfile}})
				case system.NoPicker:
					// We're not on termux/android. Treat like this:
					// $ termshark
					// # use network interface 1 - maps to
					// # termshark -i 1
					psrcs = append(psrcs, pcap.InterfaceSource{Iface: "1"})
				default:
					// We're on termux/android, but got an unexpected error.
					//if err != termshark.NoPicker {
					// !NoPicker means we could be on android/termux, but something else went wrong
					if err = system.PickFileError(err.Error()); err != nil {
						// Termux's toast ran into an error...! Maybe not installed?
						fmt.Fprintf(os.Stderr, err.Error())
					}
					return 1
				}
			} else {
				// $ cat foo.pcap | termshark
				// # use stdin - maps to
				// $ cat foo.pcap | termshark -r -
				psrcs = append(psrcs, pcap.FileSource{Filename: "-"})
			}
		}
	} else {
		// Add it to filter args. Figure out later if they're capture or display.
		filterArgs = append(filterArgs, opts.Args.FilterOrPcap)
	}

	if pcapf != "" && len(opts.Ifaces) > 0 {
		fmt.Fprintf(os.Stderr, "Please supply either a pcap or one or more live captures.\n")
		return 1
	}

	// Invariant: pcap != "" XOR len(opts.Ifaces) > 0
	if len(psrcs) == 0 {
		switch {
		case pcapf != "":
			psrcs = append(psrcs, pcap.FileSource{Filename: pcapf})
		case len(opts.Ifaces) > 0:
			for _, iface := range opts.Ifaces {
				psrcs = append(psrcs, pcap.InterfaceSource{Iface: iface})
			}
		}
	}

	// - means read from stdin. But termshark uses stdin for interacting with the UI. So if the
	// iface is -, then dup stdin to a free descriptor, adjust iface to read from that descriptor,
	// then open /dev/tty on stdin.
	newinputfd := -1

	// Here we check for
	// (a) sources named '-' - these need rewritten to /dev/fd/N and stdin needs to be moved
	// (b) fifo sources - these are switched from -r to -i because that's what tshark needs
	renamedStdin := false
	for pi, psrc := range psrcs {
		switch {
		case psrc.Name() == "-":
			if renamedStdin {
				fmt.Fprintf(os.Stderr, "Requested live capture %v (\"stdin\") cannot be supplied more than once.\n", psrc.Name())
				return 1
			}
			if termshark.IsTerminal(os.Stdin.Fd()) {
				fmt.Fprintf(os.Stderr, "Requested live capture is %v (\"stdin\") but stdin is a tty.\n", psrc.Name())
				fmt.Fprintf(os.Stderr, "Perhaps you intended to pipe packet input to termshark?\n")
				return 1
			}
			if runtime.GOOS != "windows" {
				newinputfd, err = system.MoveStdin()
				if err != nil {
					fmt.Fprintf(os.Stderr, "%v\n", err)
					return 1
				}
				psrcs[pi] = pcap.PipeSource{Descriptor: fmt.Sprintf("/dev/fd/%d", newinputfd), Fd: newinputfd}
				renamedStdin = true
			} else {
				fmt.Fprintf(os.Stderr, "Sorry, termshark does not yet support piped input on Windows.\n")
				return 1
			}
		default:
			stat, err := os.Stat(psrc.Name())
			if err != nil {
				if psrc.IsFile() || psrc.IsFifo() {
					// Means this was supplied with -r - since any file sources means there's (a) 1 and (b)
					// no other sources. So it must stat. Note if we started with -i fifo, this check
					// isn't done... but it still ought to exist.
					fmt.Fprintf(os.Stderr, "Error reading file %s: %v.\n", psrc.Name(), err)
					return 1
				}
				continue
			}
			if stat.Mode()&os.ModeNamedPipe != 0 {
				// If termshark was invoked with -r myfifo, switch to -i myfifo, which tshark uses. This
				// also puts termshark in "interface" mode where it assumes the source is unbounded
				// (e.g. a different spinner)
				psrcs[pi] = pcap.FifoSource{Filename: psrc.Name()}
			} else {
				if pcapffile, err := os.Open(psrc.Name()); err != nil {
					// Do this up front before the UI starts to catch simple errors quickly - like
					// the file not being readable. It's possible that tshark would be able to read
					// it and the termshark user not, but unlikely.
					fmt.Fprintf(os.Stderr, "Error reading file %s: %v.\n", psrc.Name(), err)
					return 1
				} else {
					pcapffile.Close()
				}
			}
		}
	}

	// Means files
	fileSrcs := pcap.FileSystemSources(psrcs)
	if len(fileSrcs) == 1 {
		if len(psrcs) > 1 {
			fmt.Fprintf(os.Stderr, "You can't specify both a pcap and a live capture.\n")
			return 1
		}
	} else if len(fileSrcs) > 1 {
		fmt.Fprintf(os.Stderr, "You can't specify more than one pcap.\n")
		return 1
	}

	// Invariant: len(psrcs) > 0
	// Invariant: len(fileSrcs) == 1 => len(psrcs) == 1

	// go-flags returns [""] when no extra args are provided, so I can't just
	// test the length of this slice
	argsFilter := strings.Join(filterArgs, " ")

	// Work out capture filter afterwards because we need to determine first
	// whether any potential first argument is intended as a pcap file instead of
	// a capture filter.
	captureFilter := opts.CaptureFilter

	// Meaning there are only live captures
	if len(fileSrcs) == 0 && argsFilter != "" {
		if opts.CaptureFilter != "" {
			fmt.Fprintf(os.Stderr, "Two capture filters provided - '%s' and '%s' - please supply one only.\n", opts.CaptureFilter, argsFilter)
			return 1
		}
		captureFilter = argsFilter
	}

	displayFilter := opts.DisplayFilter

	// Validate supplied filters e.g. no capture filter when reading from file
	if len(fileSrcs) > 0 {
		if captureFilter != "" {
			fmt.Fprintf(os.Stderr, "Cannot use a capture filter when reading from a pcap file - '%s' and '%s'.\n", captureFilter, pcapf)
			return 1
		}
		if argsFilter != "" {
			if opts.DisplayFilter != "" {
				fmt.Fprintf(os.Stderr, "Two display filters provided - '%s' and '%s' - please supply one only.\n", opts.DisplayFilter, argsFilter)
				return 1
			}
			displayFilter = argsFilter
		}
	}

	// Here we now have an accurate view of all psrcs - either file, fifo, pipe or interface

	// Helpful to use logging when enumerating interfaces below, so do it first
	if !opts.LogTty {
		logfile := termshark.CacheFile("termshark.log")
		logfd, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create log file %s: %v\n", logfile, err)
			return 1
		}
		// Don't close it - just let the descriptor be closed at exit. logrus is used
		// in many places, some outside of this main function, and closing results in
		// an error often on freebsd.
		//defer logfd.Close()
		log.SetOutput(logfd)
	}

	if cli.FlagIsTrue(opts.Debug) {
		for _, addr := range termshark.LocalIPs() {
			log.Infof("Starting debug web server at http://%s:6060/debug/pprof/", addr)
		}
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}

	for _, dir := range []string{termshark.CacheDir(), termshark.PcapDir()} {
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, 0777)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unexpected error making dir %s: %v", dir, err)
				return 1
			}
		}
	}

	// Write this pcap out here because the color validation code later depends on empty.pcap
	emptyPcap := termshark.CacheFile("empty.pcap")
	if _, err := os.Stat(emptyPcap); os.IsNotExist(err) {
		err = termshark.WriteEmptyPcap(emptyPcap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create dummy pcap %s: %v", emptyPcap, err)
			return 1
		}
	}

	tsharkBin, kverr := termshark.TSharkPath()
	if kverr != nil {
		fmt.Fprintf(os.Stderr, kverr.KeyVals["msg"].(string))
		return 1
	}

	// Here, tsharkBin is a fully-qualified tshark binary that exists on the fs (absent race
	// conditions...)

	valids := termshark.ConfStrings("main.validated-tsharks")

	if !termshark.StringInSlice(tsharkBin, valids) {
		tver, err := termshark.TSharkVersion(tsharkBin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not determine tshark version: %v\n", err)
			return 1
		}
		// This is the earliest version I could determine gives reliable results in termshark.
		// tshark compiled against tag v1.10.1 doesn't populate the hex view.
		mver, _ := semver.Make("1.10.2")
		if tver.LT(mver) {
			fmt.Fprintf(os.Stderr, "termshark will not operate correctly with a tshark older than %v (found %v)\n", mver, tver)
			return 1
		}

		valids = append(valids, tsharkBin)
		termshark.SetConf("main.validated-tsharks", valids)
	}

	// If the last tshark we used isn't the same as the current one, then remove the cached fields
	// data structure so it can be regenerated.
	if tsharkBin != termshark.ConfString("main.last-used-tshark", "") {
		termshark.DeleteCachedFields()
	}

	// Write out the last-used tshark path. We do this to make the above fields cache be consistent
	// with the tshark binary we're using.
	termshark.SetConf("main.last-used-tshark", tsharkBin)

	// Determine if the current binary supports color. Tshark will fail with an error if it's too old
	// and you supply the --color flag. Assume true, and check if our current binary is not in the
	// validate list.
	ui.PacketColorsSupported = true
	colorTsharks := termshark.ConfStrings("main.color-tsharks")

	if !termshark.StringInSlice(tsharkBin, colorTsharks) {
		ui.PacketColorsSupported, err = termshark.TSharkSupportsColor(tsharkBin)
		if err != nil {
			ui.PacketColorsSupported = false
		} else {
			colorTsharks = append(colorTsharks, tsharkBin)
			termshark.SetConf("main.color-tsharks", colorTsharks)
		}
	}

	// If any of opts.Ifaces is provided as a number, it's meant as the index of the interfaces as
	// per the order returned by the OS. useIface will always be the name of the interface.

	var systemInterfaces map[int][]string
	// See if the interface argument is an integer
	for pi, psrc := range psrcs {
		checkInterfaceName := false
		ifaceIdx := -1
		if psrc.IsInterface() {
			if i, err := strconv.Atoi(psrc.Name()); err == nil {
				ifaceIdx = i
			}

			// If it's a fifo, then always treat is as a fifo and not a reference to something in tshark -D
			if ifaceIdx != -1 {
				// if the argument is an integer, then confirm it in the output of tshark -D
				checkInterfaceName = true
			} else if runtime.GOOS == "windows" {
				// If we're on windows, then all interfaces - indices and names -
				// will be in tshark -D, so confirm it there
				checkInterfaceName = true
			}
		}

		if checkInterfaceName {
			if systemInterfaces == nil {
				systemInterfaces, err = termshark.Interfaces()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Could not enumerate network interfaces: %v\n", err)
					return 1
				}
			}

			gotit := false
			var canonicalName string
		iLoop:
			for n, i := range systemInterfaces { // (7, ["NDIS_...", "Local Area..."])
				if n == ifaceIdx {
					gotit = true
					canonicalName = i[0]
					break
				} else {
					for _, iname := range i {
						if iname == psrc.Name() {
							gotit = true
							canonicalName = i[0]
							break iLoop
						}
					}
				}
			}
			if gotit {
				// Guaranteed that psrc.IsInterface() is true
				// Use the canonical name e.g. "NDIS_...". Then the temporary filename will
				// have a more meaningful name.
				psrcs[pi] = pcap.InterfaceSource{Iface: canonicalName}
			} else {
				fmt.Fprintf(os.Stderr, "Could not find network interface %s\n", psrc.Name())
				return 1
			}
		}
	}

	watcher, err := termshark.NewConfigWatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Problem constructing config file watcher: %v", err)
		return 1
	}
	defer watcher.Close()

	//======================================================================

	// If != "", then the name of the file to which packets are saved when read from an
	// interface source. We can't just use the loader because the user might clear then load
	// a recent pcap on top of the originally loaded packets.
	ifacePcapFilename := ""

	defer func() {
		// if useIface != "" then we run dumpcap with the -i option - which
		// means the packet source is either an interface, a pipe, or a
		// fifo. In all cases, we save the packets to a file so that if a
		// filter is applied, we can restart - and so that we preserve the
		// capture at the end of running termshark.
		if len(pcap.FileSystemSources(psrcs)) == 0 && startedSuccessfully {
			fmt.Printf("Packets read from %s have been saved in %s\n", pcap.SourcesString(psrcs), ifacePcapFilename)
		}
	}()

	//======================================================================

	ifaceExitCode := 0
	var ifaceErr error

	// This is deferred until after the app is Closed - otherwise messages written to stdout/stderr are
	// swallowed by tcell.
	defer func() {
		if ifaceExitCode != 0 {
			fmt.Fprintf(os.Stderr, "Cannot capture on device %s", pcap.SourcesString(psrcs))
			if ifaceErr != nil {
				fmt.Fprintf(os.Stderr, ": %v", ifaceErr)
			}
			fmt.Fprintf(os.Stderr, " (exit code %d)\n", ifaceExitCode)
			if runtime.GOOS == "linux" && os.Geteuid() != 0 {
				fmt.Fprintf(os.Stderr, "You might need: sudo setcap cap_net_raw,cap_net_admin+eip %s\n", termshark.PrivilegedBin())
				fmt.Fprintf(os.Stderr, "Or try running with sudo or as root.\n")
			}
			fmt.Fprintf(os.Stderr, "See https://termshark.io/no-root for more info.\n")
		}
	}()

	// Initialize application state for dark mode and auto-scroll
	ui.DarkMode = termshark.ConfBool("main.dark-mode", false)
	ui.AutoScroll = termshark.ConfBool("main.auto-scroll", true)
	ui.PacketColors = termshark.ConfBool("main.packet-colors", true)

	// Set them up here so they have access to any command-line flags that
	// need to be passed to the tshark commands used
	pdmlArgs := termshark.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs := termshark.ConfStringSlice("main.psml-args", []string{})
	if opts.TimestampFormat != "" {
		psmlArgs = append(psmlArgs, "-t", opts.TimestampFormat)
	}
	tsharkArgs := termshark.ConfStringSlice("main.tshark-args", []string{})
	if ui.PacketColors && !ui.PacketColorsSupported {
		log.Warnf("Packet coloring is enabled, but %s does not support --color", tsharkBin)
		ui.PacketColors = false
	}
	cacheSize := termshark.ConfInt("main.pcap-cache-size", 64)
	bundleSize := termshark.ConfInt("main.pcap-bundle-size", 1000)
	if bundleSize <= 0 {
		maxBundleSize := 100000
		log.Infof("Config specifies pcap-bundle-size as %d - setting to max (%d)", bundleSize, maxBundleSize)
		bundleSize = maxBundleSize
	}
	ui.PcapScheduler = pcap.NewScheduler(
		pcap.MakeCommands(opts.DecodeAs, tsharkArgs, pdmlArgs, psmlArgs, ui.PacketColors),
		pcap.Options{
			CacheSize:      cacheSize,
			PacketsPerLoad: bundleSize,
		},
	)
	ui.Loader = ui.PcapScheduler.Loader

	// Buffered because I might send something in this goroutine
	startUIChan := make(chan struct{}, 1)
	// Used to cancel the display of a message telling the user why there is no UI yet.
	detectMsgChan := make(chan struct{}, 1)

	var iwatcher *fsnotify.Watcher
	var ifaceTmpFile string

	if len(pcap.FileSystemSources(psrcs)) == 0 {
		srcNames := make([]string, 0, len(psrcs))
		for _, psrc := range psrcs {
			srcNames = append(srcNames, psrc.Name())
		}
		ifaceTmpFile = pcap.TempPcapFile(srcNames...)

		iwatcher, err = fsnotify.NewWatcher()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not start filesystem watcher: %v\n", err)
			return 1
		}
		defer func() {
			if iwatcher != nil {
				iwatcher.Close()
			}
		}()

		// Don't start the UI until this file is created. When listening on a pipe,
		// termshark will start a process similar to:
		//
		// dumpcap -i /dev/fd/3 -w ~/.cache/pcaps/tmp123.pcap
		//
		// dumpcap will not actually create that file until it has data to write to it.
		// So we watch for the creation of that file, and until then, don't launch the UI.
		// Then if the feeding process needs input first e.g. sudo tcpdump needs password,
		// there won't be a conflict for reading /dev/tty.
		//
		if err := iwatcher.Add(termshark.PcapDir()); err != nil { //&& !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Could not set up watcher for %s: %v\n", termshark.PcapDir(), err)
			return 1
		}

		fmt.Printf("(The termshark UI will start when packets are detected...)\n")

	} else {
		// Start UI right away, reading from a file
		startUIChan <- struct{}{}
	}

	// Do this before ui.Build. If ui.Build fails (e.g. bad TERM), then the filter will be left
	// running, so we need the defer to be in effect here and not after the processing of ui.Build's
	// error
	defer func() {
		if ui.FilterWidget != nil {
			ui.FilterWidget.Close()
		}
	}()

	var app *gowid.App
	if app, err = ui.Build(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// Tcell returns ExitError now because if its internal terminfo DB does not have
		// a matching entry, it tries to build one with infocmp.
		if _, ok := termshark.RootCause(err).(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "Termshark could not recognize your terminal. Try changing $TERM.\n")
		}
		return 1
	}

	appRunner := app.Runner()

	// Populate the filter widget initially - runs asynchronously
	go ui.FilterWidget.UpdateCompletions(app)

	ui.Running = false

	validator := filter.Validator{
		Invalid: &filter.ValidateCB{
			App: app,
			Fn: func(app gowid.IApp) {
				if !ui.Running {
					fmt.Fprintf(os.Stderr, "Invalid filter: %s\n", displayFilter)
					ui.QuitRequestedChan <- struct{}{}
				} else {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						ui.OpenError(fmt.Sprintf("Invalid filter: %s", displayFilter), app)
					}))
				}
			},
		},
	}

	// Refresh
	fileSrcs = pcap.FileSystemSources(psrcs)
	if len(fileSrcs) > 0 {
		psrc := fileSrcs[0]
		absfile, err := filepath.Abs(psrc.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not determine working directory: %v\n", err)
			return 1
		}

		doit := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.FilterWidget.SetValue(displayFilter, app)
			}))
			ui.RequestLoadPcapWithCheck(absfile, displayFilter, app)
		}
		validator.Valid = &filter.ValidateCB{Fn: doit, App: app}
		validator.Validate(displayFilter)
		// no auto-scroll when reading a file
		ui.AutoScroll = false
	} else {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		ifaceExitCode = 0
		for _, psrc := range psrcs {
			if psrc.IsInterface() {
				if ifaceExitCode, ifaceErr = termshark.RunForExitCode(
					termshark.CaptureBin(),
					[]string{"-i", psrc.Name(), "-a", "duration:1"},
					append(os.Environ(), "TERMSHARK_CAPTURE_MODE=1"),
				); ifaceExitCode != 0 {
					return 1
				}
			} else {
				// We only test one - the assumption is that if dumpcap can read from eth0, it can also read from eth1, ... And
				// this lets termshark start up more quickly.
				break
			}
		}

		ifValid := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.FilterWidget.SetValue(displayFilter, app)
			}))
			ifacePcapFilename = ifaceTmpFile
			ui.PcapScheduler.RequestLoadInterfaces(psrcs, captureFilter, displayFilter, ifaceTmpFile,
				pcap.HandlerList{
					ui.MakeSaveRecents("", displayFilter, app),
					ui.MakePacketViewUpdater(app),
					ui.MakeUpdateCurrentCaptureInTitle(app),
					ui.ManageStreamCache{},
				},
			)
		}
		validator.Valid = &filter.ValidateCB{Fn: ifValid, App: app}
		validator.Validate(displayFilter)
	}

	quitRequested := false
	quitIssuedToApp := false
	prevstate := ui.Loader.State()
	var prev float64

	progTicker := time.NewTicker(time.Duration(200) * time.Millisecond)

	loaderPsmlFinChan := ui.Loader.PsmlFinishedChan
	loaderIfaceFinChan := ui.Loader.IfaceFinishedChan
	loaderPdmlFinChan := ui.Loader.Stage2FinishedChan

	ctrlzLineDisc := tty.TerminalSignals{}

	// This is used to stop iface load and any stream reassembly. Make sure to
	// avoid any stream reassembly errors, since this is a controlled shutdown
	// but the tshark processes reading data for stream reassembly may still
	// complain about interruptions
	stopLoaders := func() {
		if ui.StreamLoader != nil {
			ui.StreamLoader.SuppressErrors = true
		}
		ui.Loader.SuppressErrors = true
		ui.Loader.Close()
	}

	inactiveDuration := 30 * time.Second
	inactivityTimer := time.NewTimer(inactiveDuration)

Loop:
	for {
		var finChan <-chan time.Time
		var opsChan <-chan pcap.RunFn
		var tickChan <-chan time.Time
		var inactivityChan <-chan time.Time
		var emptyStructViewChan <-chan time.Time
		var emptyHexViewChan <-chan time.Time
		var psmlFinChan <-chan struct{}
		var ifaceFinChan <-chan struct{}
		var pdmlFinChan <-chan struct{}
		var tmpPcapWatcherChan <-chan fsnotify.Event
		var tmpPcapWatcherErrorsChan <-chan error
		var tcellEvents <-chan tcell.Event
		var afterRenderEvents <-chan gowid.IAfterRenderEvent
		// For setting struct views empty. This isn't done as soon as a load is initiated because
		// in the case we are loading from an interface and following new packets, we get an ugly
		// blinking effect where the loading message is displayed, shortly followed by the struct or
		// hex view which comes back from the pdml process (because the pdml process can only read
		// up to the end of the currently seen packets, each time it has to start afresh from the
		// beginning to get new packets). Waiting 500ms to display loading gives enough time, in
		// practice,

		if ui.EmptyStructViewTimer != nil {
			emptyStructViewChan = ui.EmptyStructViewTimer.C
		}
		// For setting hex views empty
		if ui.EmptyHexViewTimer != nil {
			emptyHexViewChan = ui.EmptyHexViewTimer.C
		}

		// This should really be moved to a handler...
		if ui.Loader.State() == 0 {
			if prevstate != 0 {
				// If the state has just switched to 0, it means no interface-reading process is
				// running. That means we will no longer be reading from an interface or a fifo, so
				// we point the loader at the file we wrote to the cache, and redirect all
				// loads/filters to that now.
				ui.Loader.TurnOffPipe()
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.ClearProgressWidget(app)
					ui.SetProgressDeterminate(app) // always switch back - for pdml (partial) loads of later data.
				}))
				// When the progress bar is enabled, track the previous percentage reached. This is
				// so that I don't go "backwards" if I generate a progress value less than the last
				// one, using the current algorithm (because it would be confusing to see it go
				// backwards)
				prev = 0.0
			}

			if quitRequested {
				if ui.Running {
					if !quitIssuedToApp {
						app.Quit()
						quitIssuedToApp = true // Avoid closing app twice - doubly-closed channel
					}
				} else {
					// No UI so exit loop immediately
					break Loop
				}
			}
		}

		if ui.Loader.State()&(pcap.LoadingPdml|pcap.LoadingPsml) != 0 {
			tickChan = progTicker.C // progress is only enabled when a pcap may be loading
		}

		if ui.Loader.State()&pcap.LoadingPdml != 0 {
			pdmlFinChan = loaderPdmlFinChan
		}

		if ui.Loader.State()&pcap.LoadingPsml != 0 {
			psmlFinChan = loaderPsmlFinChan
		}

		if ui.Loader.State()&pcap.LoadingIface != 0 {
			ifaceFinChan = loaderIfaceFinChan
			inactivityChan = inactivityTimer.C
		}

		// (User) operations are enabled by default (the test predicate is nil), or if the predicate returns true
		// meaning the operation has reached its desired state. Only one operation can be in progress at a time.
		if ui.PcapScheduler.IsEnabled() {
			opsChan = ui.PcapScheduler.OperationsChan
		}

		// This tracks a temporary pcap file which is populated by dumpcap when termshark is
		// reading from a fifo. If iwatcher is nil, it means we've got data and don't need to
		// monitor any more.
		if iwatcher != nil {
			tmpPcapWatcherChan = iwatcher.Events
			tmpPcapWatcherErrorsChan = iwatcher.Errors
		}

		// Only process tcell and gowid events if the UI is running.
		if ui.Running {
			tcellEvents = app.TCellEvents
		}

		if ui.Fin != nil && ui.Fin.Active() {
			finChan = ui.Fin.C()
		}

		afterRenderEvents = app.AfterRenderEvents

		prevstate = ui.Loader.State()

		select {

		case <-inactivityChan:
			ui.Fin.Activate()
			app.Redraw()

		case <-finChan:
			ui.Fin.Advance()
			app.Redraw()

		case we := <-tmpPcapWatcherChan:
			if strings.Contains(we.Name, ifaceTmpFile) {
				log.Infof("Pcap file %v has appeared - launching UI", we.Name)
				iwatcher.Close()
				iwatcher = nil
				startUIChan <- struct{}{}
			}

		case err := <-tmpPcapWatcherErrorsChan:
			fmt.Fprintf(os.Stderr, "Unexpected watcher error for %s: %v", ifaceTmpFile, err)
			return 1

		case <-startUIChan:
			log.Infof("Launching termshark UI")

			// Go to termshark UI view
			if err = app.ActivateScreen(); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting UI: %v\n", err)
				return 1
			}

			// Start tcell/gowid events for keys, etc
			appRunner.Start()

			// Reinstate  our terminal overrides that allow ctrl-z
			if err := ctrlzLineDisc.Set(); err != nil {
				ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
			}

			ui.Running = true
			startedSuccessfully = true

			close(startUIChan)
			startUIChan = nil // make sure it's not triggered again

			close(detectMsgChan) // don't display the message about waiting for the UI

			defer func() {
				// Do this to make sure the program quits quickly if quit is invoked
				// mid-load. It's safe to call this if a pcap isn't being loaded.
				//
				// The regular stopLoadPcap will send a signal to pcapChan. But if app.quit
				// is called, the main select{} loop will be broken, and nothing will listen
				// to that channel. As a result, nothing stops a pcap load. This calls the
				// context cancellation function right away
				stopLoaders()

				appRunner.Stop()
				app.Close()
				ui.Running = false
			}()

		case <-ui.QuitRequestedChan:
			quitRequested = true
			if ui.Loader.State() != 0 {
				// We know we're not idle, so stop any load so the quit op happens quickly for the user. Quit
				// will happen next time round because the quitRequested flag is checked.
				stopLoaders()
			}

		case sig := <-sigChan:
			if system.IsSigTSTP(sig) {
				if ui.Running {
					// Remove our terminal overrides that allow ctrl-z
					ctrlzLineDisc.Restore()
					// Stop tcell/gowid events for keys, etc
					appRunner.Stop()
					// Go back to terminal view
					app.DeactivateScreen()

					ui.Running = false
					uiSuspended = true

				} else {
					log.Infof("UI not active - no terminal changes required.")
				}

				// This is not synchronous, but some time after calling this, we'll be suspended.
				if err := system.StopMyself(); err != nil {
					fmt.Fprintf(os.Stderr, "Unexpected error issuing SIGSTOP: %v\n", err)
					return 1
				}

			} else if system.IsSigCont(sig) {
				if uiSuspended {
					// Go to termshark UI view
					if err = app.ActivateScreen(); err != nil {
						fmt.Fprintf(os.Stderr, "Error starting UI: %v\n", err)
						return 1
					}

					// Start tcell/gowid events for keys, etc
					appRunner.Start()

					// Reinstate  our terminal overrides that allow ctrl-z
					if err := ctrlzLineDisc.Set(); err != nil {
						ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
					}

					ui.Running = true
					uiSuspended = false
				}
			} else if system.IsSigUSR1(sig) {
				if cli.FlagIsTrue(opts.Debug) {
					termshark.ProfileCPUFor(20)
				} else {
					log.Infof("SIGUSR1 ignored by termshark - see the --debug flag")
				}

			} else if system.IsSigUSR2(sig) {
				if cli.FlagIsTrue(opts.Debug) {
					termshark.ProfileHeap()
				} else {
					log.Infof("SIGUSR2 ignored by termshark - see the --debug flag")
				}

			} else {
				log.Infof("Starting termination via signal %v", sig)
				ui.QuitRequestedChan <- struct{}{}
			}

		case fn := <-opsChan:
			// We run the requested operation - because operations are now enabled, since this channel
			// is listening - and the result tells us when operations can be re-enabled (i.e. the target
			// state of the operation just started, for example). This means we can let an operation
			// "complete", moving through a sequence of states to the final state, befpre accepting
			// another request.
			fn()

		case <-ui.CacheRequestsChan:
			ui.CacheRequests = pcap.ProcessPdmlRequests(ui.CacheRequests, ui.Loader,
				struct {
					ui.SetNewPdmlRequests
					ui.SetStructWidgets
				}{
					ui.SetNewPdmlRequests{ui.PcapScheduler},
					ui.SetStructWidgets{ui.Loader, app},
				})

		case <-ifaceFinChan:
			// this state change only happens if the load from the interface is explicitly
			// stopped by the user (e.g. the stop button). When the current data has come
			// from loading from an interface, when stopped we still want to be able to filter
			// on that data. So the load routines should treat it like a regular pcap
			// (until the interface is started again). That means the psml reader should read
			// from the file and not the fifo.
			loaderIfaceFinChan = ui.Loader.IfaceFinishedChan
			ui.Loader.SetState(ui.Loader.State() & ^pcap.LoadingIface)

		case <-psmlFinChan:
			if ui.Loader.LoadWasCancelled {
				// Don't reset cancel state here. If, after stopping an interface load, I
				// apply a filter, I need to know if the load was cancelled previously because
				// if it was cancelled, I need to load from the temp pcap; if not cancelled,
				// (meaning still running), then I just apply a new filter and have the pcap
				// reader read from the fifo. Only do this if the user isn't quitting the app,
				// otherwise it looks clumsy.
				if !quitRequested {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						ui.OpenError("Loading was cancelled.", app)
					}))
				}
			}
			// Reset
			loaderPsmlFinChan = ui.Loader.PsmlFinishedChan
			ui.Loader.SetState(ui.Loader.State() & ^pcap.LoadingPsml)

		case <-pdmlFinChan:
			loaderPdmlFinChan = ui.Loader.Stage2FinishedChan
			ui.Loader.SetState(ui.Loader.State() & ^pcap.LoadingPdml)

		case <-tickChan:
			if system.HaveFdinfo && (ui.Loader.State() == pcap.LoadingPdml || !ui.Loader.ReadingFromFifo()) {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					prev = ui.UpdateProgressBarForFile(ui.Loader, prev, app)
				}))
			} else {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.UpdateProgressBarForInterface(ui.Loader, app)
				}))
			}

		case <-emptyStructViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.SetStructViewMissing(app)
				ui.StopEmptyStructViewTimer()
			}))

		case <-emptyHexViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.SetHexViewMissing(app)
				ui.StopEmptyHexViewTimer()
			}))

		case ev := <-tcellEvents:
			app.HandleTCellEvent(ev, gowid.IgnoreUnhandledInput)
			inactivityTimer.Reset(inactiveDuration)

		case ev, ok := <-afterRenderEvents:
			// This means app.Quit() has been called, which closes the AfterRenderEvents
			// channel - and then will accept no more events. select will then return
			// nil on this channel - which we then use to break the loop
			if !ok {
				break Loop
			}
			app.RunThenRenderEvent(ev)

		case <-watcher.ConfigChanged():
			// Re-read so changes that can take effect immediately do so
			if err := viper.ReadInConfig(); err != nil {
				log.Warnf("Unexpected error re-reading toml config: %v", err)
			}
			ui.UpdateRecentMenu(app)
		}

	}

	return 0
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
