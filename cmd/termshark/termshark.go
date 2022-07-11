// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main

import (
	"bytes"
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
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/capinfo"
	"github.com/gcla/termshark/v2/pkg/cli"
	"github.com/gcla/termshark/v2/pkg/confwatcher"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/pkg/streams"
	"github.com/gcla/termshark/v2/pkg/summary"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/pkg/tailfile"
	"github.com/gcla/termshark/v2/pkg/tty"
	"github.com/gcla/termshark/v2/ui"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/wormhole"
	"github.com/gdamore/tcell/v2"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"

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
	pcap.Goroutinewg = &ensureGoroutinesStopWG
	streams.Goroutinewg = &ensureGoroutinesStopWG
	capinfo.Goroutinewg = &ensureGoroutinesStopWG
	convs.Goroutinewg = &ensureGoroutinesStopWG
	ui.Goroutinewg = &ensureGoroutinesStopWG
	wormhole.Goroutinewg = &ensureGoroutinesStopWG
	summary.Goroutinewg = &ensureGoroutinesStopWG
	confwatcher.Goroutinewg = &ensureGoroutinesStopWG

	res := cmain()
	ensureGoroutinesStopWG.Wait()

	if !termshark.ShouldSwitchTerminal && !termshark.ShouldSwitchBack {
		os.Exit(res)
	}

	os.Clearenv()
	for _, e := range termshark.OriginalEnv {
		ks := strings.SplitN(e, "=", 2)
		if len(ks) == 2 {
			os.Setenv(ks[0], ks[1])
		}
	}

	exe, err := os.Executable()
	if err != nil {
		log.Warnf("Unexpected error determining termshark executable: %v", err)
		os.Exit(1)
	}

	switch {
	case termshark.ShouldSwitchTerminal:
		os.Setenv("TERMSHARK_ORIGINAL_TERM", os.Getenv("TERM"))
		os.Setenv("TERM", fmt.Sprintf("%s-256color", os.Getenv("TERM")))
	case termshark.ShouldSwitchBack:
		os.Setenv("TERM", os.Getenv("TERMSHARK_ORIGINAL_TERM"))
		os.Setenv("TERMSHARK_ORIGINAL_TERM", "")
	}

	// Need exec because we really need to re-initialize everything, including have
	// all init() functions be called again
	err = syscall.Exec(exe, os.Args, os.Environ())
	if err != nil {
		log.Warnf("Unexpected error exec-ing termshark %s: %v", exe, err)
		res = 1
	}

	os.Exit(res)
}

func cmain() int {
	startedSuccessfully := false // true if we reached the point where packets were received and the UI started.
	uiSuspended := false         // true if the UI was suspended due to SIGTSTP

	// Preserve in case we need to re-exec e.g. if the user switches TERM
	termshark.OriginalEnv = os.Environ()

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

	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Cache)
	if err := dirs[0].CreateParentDir("dummy"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create cache dir: %v\n", err)
	}
	dirs = stdConf.QueryFolders(configdir.Global)
	if err := dirs[0].CreateParentDir("dummy"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create config dir: %v\n", err)
	} else {
		if err = os.MkdirAll(filepath.Join(dirs[0].Path, "profiles"), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create profiles dir: %v\n", err)
		}
	}

	err := profiles.ReadDefaultConfig(dirs[0].Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", err.Error()))
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

	// On Windows, termshark itself is used to tail the pcap generated by dumpcap, and the output
	// is fed into tshark -T psml ...
	if tsopts.TailFileValue() != "" {
		err = tailfile.Tail(tsopts.TailFileValue())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)
			return 1
		} else {
			return 0
		}
	}

	// From here, the current profile is referenced. So load it up prior to first use. If the user
	// provides a non-existent profile name, it should be an error, just as for Wireshark.
	if tsopts.Profile != "" {
		if err = profiles.Use(tsopts.Profile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
	}

	// If this variable is set, it's set by termshark internally, and termshark is guaranteed to
	// construct a valid command-line invocation. So it doesn't matter if I do this after the CLI
	// parsing logic because there's no risk of an error causing a short-circuit and this command
	// not being run. The reason to do it after the CLI parsing logic is so that I have the correct
	// config profile loaded, needed for the tshark command.
	if os.Getenv("TERMSHARK_CAPTURE_MODE") == "1" {
		err = system.DumpcapExt(termshark.DumpcapBin(), termshark.TSharkBin(), os.Args[1:]...)
		if err != nil {
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

	// Allow the user to override the shell's TERM variable this way. Perhaps the user runs
	// under screen/tmux, and the TERM variable doesn't reflect the fact their preferred
	// terminal emumlator supports 256 colors.
	termVar := profiles.ConfString("main.term", "")
	if termVar != "" {
		fmt.Fprintf(os.Stderr, "Configuration file overrides TERM setting, using TERM=%s\n", termVar)
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

	// Here we check for
	// (a) sources named '-' - these need rewritten to /dev/fd/N and stdin needs to be moved
	// (b) fifo sources - these are switched from -r to -i because that's what tshark needs
	haveStdin := false
	for pi, psrc := range psrcs {
		switch {
		case psrc.Name() == "-":
			if haveStdin {
				fmt.Fprintf(os.Stderr, "Requested live capture %v (\"stdin\") cannot be supplied more than once.\n", psrc.Name())
				return 1
			}

			if termshark.IsTerminal(os.Stdin.Fd()) {
				fmt.Fprintf(os.Stderr, "Requested live capture is %v (\"stdin\") but stdin is a tty.\n", psrc.Name())
				fmt.Fprintf(os.Stderr, "Perhaps you intended to pipe packet input to termshark?\n")
				return 1
			}
			if runtime.GOOS != "windows" {
				psrcs[pi] = pcap.PipeSource{Descriptor: "/dev/fd/0", Fd: int(os.Stdin.Fd())}
				haveStdin = true
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
	termshark.ReverseStringSlice(filterArgs)
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

	// -w something
	if opts.WriteTo != "" {
		if len(fileSrcs) > 0 {
			fmt.Fprintf(os.Stderr, "The -w flag is incompatible with regular capture sources %v\n", fileSrcs)
			return 1
		}
		if opts.WriteTo == "-" {
			fmt.Fprintf(os.Stderr, "Cannot set -w to stdout. Target file must be regular or a symlink.\n")
			return 1
		}
		// If the file does not exist, then proceed. If it does exist, check it is something "normal".
		if _, err = os.Stat(string(opts.WriteTo)); err == nil || !os.IsNotExist(err) {
			if !system.FileRegularOrLink(string(opts.WriteTo)) {
				fmt.Fprintf(os.Stderr, "Cannot set -w to %s. Target file must be regular or a symlink.\n", opts.WriteTo)
				return 1
			}
		}
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

	debug := false
	if (opts.Debug.Set && opts.Debug.Val == true) || (!opts.Debug.Set && profiles.ConfBool("main.debug", false)) {
		debug = true
	}

	if debug {
		for _, addr := range termshark.LocalIPs() {
			log.Infof("Starting debug web server at http://%s:6060/debug/pprof/", addr)
		}
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}

	for _, dir := range []string{termshark.CacheDir(), termshark.DefaultPcapDir(), termshark.PcapDir()} {
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

	valids := profiles.ConfStrings("main.validated-tsharks")

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
		profiles.SetConf("main.validated-tsharks", valids)
	}

	// If the last tshark we used isn't the same as the current one, then remove the cached fields
	// data structure so it can be regenerated.
	if tsharkBin != profiles.ConfString("main.last-used-tshark", "") {
		fields.DeleteCachedFields()
	}

	// Write out the last-used tshark path. We do this to make the above fields cache be consistent
	// with the tshark binary we're using.
	profiles.SetConf("main.last-used-tshark", tsharkBin)

	// Determine if the current binary supports color. Tshark will fail with an error if it's too old
	// and you supply the --color flag. Assume true, and check if our current binary is not in the
	// validate list.
	ui.PacketColorsSupported = true
	colorTsharks := profiles.ConfStrings("main.color-tsharks")

	if !termshark.StringInSlice(tsharkBin, colorTsharks) {
		ui.PacketColorsSupported, err = termshark.TSharkSupportsColor(tsharkBin)
		if err != nil {
			ui.PacketColorsSupported = false
		} else {
			colorTsharks = append(colorTsharks, tsharkBin)
			profiles.SetConf("main.color-tsharks", colorTsharks)
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

	watcher, err := confwatcher.New()
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
		if len(pcap.FileSystemSources(psrcs)) == 0 && startedSuccessfully && !ui.WriteToSelected && !ui.WriteToDeleted {
			fmt.Fprintf(os.Stderr, "Packets read from %s have been saved in %s\n", pcap.SourcesString(psrcs), ifacePcapFilename)
		}
	}()

	//======================================================================

	ifaceExitCode := 0
	stderr := &bytes.Buffer{}
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
			if stderr.Len() != 0 {
				// The default capture bin is termshark itself, with a special environment
				// variable set that causes it to try dumpcap, then tshark, in that order (for
				// efficiency of capture, but falling back to tshark for extcap interfaces).
				// But telling the user the capture process is "termshark" is misleading.
				cbin, err1 := filepath.Abs(filepath.FromSlash(termshark.CaptureBin()))
				def, err2 := filepath.Abs("termshark")
				if err1 == nil && err2 == nil && cbin == def {
					cbin = "the capture process"
				}

				fmt.Fprintf(os.Stderr, "Standard error stream from %s:\n", cbin)
				fmt.Fprintf(os.Stderr, "------\n%s\n------\n", stderr.String())
			}
			if runtime.GOOS == "linux" && os.Geteuid() != 0 {
				fmt.Fprintf(os.Stderr, "You might need: sudo setcap cap_net_raw,cap_net_admin+eip %s\n", termshark.PrivilegedBin())
				fmt.Fprintf(os.Stderr, "Or try running with sudo or as root.\n")
			}
			fmt.Fprintf(os.Stderr, "See https://termshark.io/no-root for more info.\n")
		}
	}()

	// Initialize application state for dark mode and auto-scroll
	ui.DarkMode = profiles.ConfBool("main.dark-mode", true)
	ui.AutoScroll = profiles.ConfBool("main.auto-scroll", true)
	ui.PacketColors = profiles.ConfBool("main.packet-colors", true)

	// Set them up here so they have access to any command-line flags that
	// need to be passed to the tshark commands used
	pdmlArgs := profiles.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs := profiles.ConfStringSlice("main.psml-args", []string{})
	if opts.TimestampFormat != "" {
		psmlArgs = append(psmlArgs, "-t", opts.TimestampFormat)
	}
	tsharkArgs := profiles.ConfStringSlice("main.tshark-args", []string{})
	if ui.PacketColors && !ui.PacketColorsSupported {
		log.Warnf("Packet coloring is enabled, but %s does not support --color", tsharkBin)
		ui.PacketColors = false
	}
	cacheSize := profiles.ConfInt("main.pcap-cache-size", 64)
	bundleSize := profiles.ConfInt("main.pcap-bundle-size", 1000)
	if bundleSize <= 0 {
		maxBundleSize := 100000
		log.Infof("Config specifies pcap-bundle-size as %d - setting to max (%d)", bundleSize, maxBundleSize)
		bundleSize = maxBundleSize
	}

	var ifaceTmpFile string
	var waitingForPackets bool

	// no file sources - so interface or fifo
	if len(pcap.FileSystemSources(psrcs)) == 0 {
		if opts.WriteTo != "" {
			ifaceTmpFile = string(opts.WriteTo)
			ui.WriteToSelected = true
		} else {
			srcNames := make([]string, 0, len(psrcs))
			for _, psrc := range psrcs {
				srcNames = append(srcNames, psrc.Name())
			}
			ifaceTmpFile = pcap.TempPcapFile(srcNames...)
		}
		waitingForPackets = true
	} else {
		// Start UI right away, reading from a file
		close(ui.StartUIChan)
	}

	// Need to figure out possible changes to COLORTERM before creating the
	// tcell screen. Note that even though apprunner.Start() below will create
	// a new screen, it will use a terminfo that it constructed the first time
	// we call NewApp(), because tcell stores these in a global map. So if the
	// first terminfo is created in an environment with COLORTERM=truecolor,
	// the terminfo Go struct is extended with codes that emit truecolor-compatible
	// ansi codes for colors. Then if I later create a new screen without COLORTERM,
	// tcell will still use the extended terminfo struct and emit truecolor-codes
	// anyway.
	//
	// If you are using base16-shell, the lowest colors 0-21 in the 256 color space
	// will be remapped to whatever colors the terminal base16 theme sets up. If you
	// are using a termshark theme that expresses colors in RGB style (#7799AA), and
	// termshark is running in a 256-color terminal, then termshark will find the closest
	// match for the RGB color in the 256 color-space. But termshark assumes that colors
	// 0-21 are set up normally, and not remapped. If the closest match is one of those
	// colors, then the theme won't look as expected. A workaround is to tell
	// gowid not to use colors 0-21 when finding the closest match.
	if profiles.ConfKeyExists("main.ignore-base16-colors") {
		gowid.IgnoreBase16 = profiles.ConfBool("main.ignore-base16-colors", false)
	} else {
		// Try to auto-detect whether or not base16-shell is installed and in-use
		gowid.IgnoreBase16 = (os.Getenv("BASE16_SHELL") != "")
	}
	if gowid.IgnoreBase16 {
		log.Infof("Will not consider colors 0-21 from the terminal 256-color-space when interpolating theme colors")
		// If main.respect-colorterm=true then termshark will leave COLORTERM set and use
		// 24-bit color if possible. The problem with this, in the presence of base16, is that
		// some terminal-emulators - e.g. gnome-terminal - still seems to map RGB ANSI codes
		// colors that are set at values 0-21 in the 256-color space. I'm not sure if this is
		// just an implementation snafu, or if something else is going on... In any case,
		// termshark will fall back to 256-colors if base16 is detected because I can
		// programmatically avoid choosing colors 0-21 for anything termshark needs.
		if os.Getenv("COLORTERM") != "" && !profiles.ConfBool("main.respect-colorterm", false) {
			log.Infof("Pessimistically disabling 24-bit color to avoid conflicts with base16")
			os.Unsetenv("COLORTERM")
		}
	}

	// the app variable is created here so I can bind it in the defer below
	var app *gowid.App

	// Do this before ui.Build. If ui.Build fails (e.g. bad TERM), then the filter will be left
	// running, so we need the defer to be in effect here and not after the processing of ui.Build's
	// error
	defer func() {
		if ui.FilterWidget != nil {
			ui.FilterWidget.Close()
		}
		if ui.SearchWidget != nil {
			ui.SearchWidget.Close(app)
		}
		if ui.CurrentWormholeWidget != nil {
			ui.CurrentWormholeWidget.Close()
		}
		if ui.CurrentColsWidget != nil {
			ui.CurrentColsWidget.Close()
		}
	}()

	if app, err = ui.Build(usetty); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// Tcell returns ExitError now because if its internal terminfo DB does not have
		// a matching entry, it tries to build one with infocmp.
		if _, ok := termshark.RootCause(err).(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "Termshark could not recognize your terminal. Try changing $TERM.\n")
		}
		return 1
	}

	appRunner := app.Runner()

	pcap.PcapCmds = pcap.MakeCommands(opts.DecodeAs, tsharkArgs, pdmlArgs, psmlArgs, ui.PacketColors)
	pcap.PcapOpts = pcap.Options{
		CacheSize:      cacheSize,
		PacketsPerLoad: bundleSize,
	}

	// This is a global. The type supports swapping out the real loader by embedding it via
	// pointer, but I assume this only happens in the main goroutine.
	ui.Loader = &pcap.PacketLoader{ParentLoader: pcap.NewPcapLoader(pcap.PcapCmds, &pcap.Runner{app}, pcap.PcapOpts)}

	// Populate the filter widget initially - runs asynchronously
	go ui.FilterWidget.UpdateCompletions(app)

	ui.Running = false

	validator := filter.DisplayFilterValidator{
		Invalid: &filter.ValidateCB{
			App: app,
			Fn: func(app gowid.IApp) {
				if !ui.Running {
					fmt.Fprintf(os.Stderr, "Invalid filter: %s\n", displayFilter)
					ui.RequestQuit()
				} else {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						ui.OpenError(fmt.Sprintf("Invalid filter: %s", displayFilter), app)
					}))
				}
			},
		},
	}

	// Do this before the load starts, so that the PSML process has a guaranteed safe
	// PSML column format to use when it begins. The call to RequestLoadPcapWithCheck,
	// for example, will access the setting for preferred PSML columns.
	//
	// Init a global variable with the list of all valid tshark columns and
	// their formats. This might start a tshark process if the data isn't
	// cached. If so, print a message to console - "initializing". I'm not doing
	// anything smarter or async - it's not worth it, this should take a fraction
	// of a second.
	err = shark.InitValidColumns()

	// If this message is needed, we want it to appear after the init message for the packet
	// columns - after InitValidColumns
	if waitingForPackets {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("(The termshark UI will start when packets are detected on %s...)\n",
			strings.Join(pcap.SourcesNames(psrcs), " or ")))
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
			ui.RequestLoadPcap(absfile, displayFilter, ui.NoGlobalJump, app)
		}
		validator.Valid = &filter.ValidateCB{Fn: doit, App: app}
		validator.EmptyCB = &filter.ValidateCB{Fn: doit, App: app}
		validator.Validate(displayFilter)
	} else {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		ifaceExitCode = 0
		for _, psrc := range psrcs {
			if psrc.IsInterface() {
				if ifaceExitCode, ifaceErr = termshark.RunForStderr(
					termshark.CaptureBin(),
					[]string{"-i", psrc.Name(), "-a", "duration:1"},
					append(os.Environ(), "TERMSHARK_CAPTURE_MODE=1"),
					stderr,
				); ifaceExitCode != 0 {
					return 1
				}
			} else {
				// We only test one - the assumption is that if dumpcap can read from eth0, it can also read from eth1, ... And
				// this lets termshark start up more quickly.
				break
			}
		}

		doLoad := func(app gowid.IApp) {
			ifacePcapFilename = ifaceTmpFile
			ui.RequestLoadInterfaces(psrcs, captureFilter, displayFilter, ifaceTmpFile, app)
		}

		ifValid := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.FilterWidget.SetValue(displayFilter, app)
			}))
			doLoad(app)
		}

		validator.Valid = &filter.ValidateCB{Fn: ifValid, App: app}
		validator.EmptyCB = &filter.ValidateCB{Fn: doLoad, App: app}
		validator.Validate(displayFilter)
	}

	quitIssuedToApp := false

	wasLoadingPdmlLastTime := ui.Loader.PdmlLoader.IsLoading()
	wasLoadingAnythingLastTime := ui.Loader.LoadingAnything()

	// Keep track of this across runs of the main loop so we don't go backwards (because
	// that looks wrong to the user)
	var prevProgPercentage float64

	progTicker := time.NewTicker(time.Duration(200) * time.Millisecond)

	ctrlzLineDisc := tty.TerminalSignals{}

	// This is used to stop iface load and any stream reassembly. Make sure to
	// avoid any stream reassembly errors, since this is a controlled shutdown
	// but the tshark processes reading data for stream reassembly may still
	// complain about interruptions
	stopLoaders := func() {
		if ui.StreamLoader != nil {
			ui.StreamLoader.SuppressErrors = true
		}
		ui.Loader.CloseMain()
	}

	inactiveDuration := 60 * time.Second
	inactivityTimer := time.NewTimer(inactiveDuration)
	currentlyInactive := false // True if the timer has fired and termshark is in "inactive" state

	var progCancelTimer *time.Timer

	checkedPcapCache := false
	checkPcapCacheDuration := 5 * time.Second
	checkPcapCacheTimer := time.NewTimer(checkPcapCacheDuration)

Loop:
	for {
		var finChan <-chan time.Time
		var tickChan <-chan time.Time
		var inactivityChan <-chan time.Time
		var checkPcapCacheChan <-chan time.Time
		var tcellEvents <-chan tcell.Event
		var opsChan <-chan gowid.RunFunction
		var afterRenderEvents <-chan gowid.IAfterRenderEvent
		// For setting struct views empty. This isn't done as soon as a load is initiated because
		// in the case we are loading from an interface and following new packets, we get an ugly
		// blinking effect where the loading message is displayed, shortly followed by the struct or
		// hex view which comes back from the pdml process (because the pdml process can only read
		// up to the end of the currently seen packets, each time it has to start afresh from the
		// beginning to get new packets). Waiting 500ms to display loading gives enough time, in
		// practice,

		// On change of state - check for new pdml requests
		if ui.Loader.PdmlLoader.IsLoading() != wasLoadingPdmlLastTime {
			ui.CacheRequestsChan <- struct{}{}
		}

		// This should really be moved to a handler...
		if !ui.Loader.LoadingAnything() {
			if wasLoadingAnythingLastTime {
				// If the state has just switched to 0, it means no interface-reading process is
				// running. That means we will no longer be reading from an interface or a fifo, so
				// we point the loader at the file we wrote to the cache, and redirect all
				// loads/filters to that now.
				ui.Loader.TurnOffPipe()
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.ClearProgressWidgetFor(app, ui.LoaderOwns)
					ui.SetProgressDeterminateFor(app, ui.LoaderOwns) // always switch back - for pdml (partial) loads of later data.
				}))

				// When the progress bar is enabled, track the previous percentage reached. This is
				// so that I don't go "backwards" if I generate a progress value less than the last
				// one, using the current algorithm (because it would be confusing to see it go
				// backwards)
				prevProgPercentage = 0.0
			}

			// EnableOpsVar will be enabled when all the handlers have run, which happen in the main goroutine.
			// I need them to run because the loader channel is closed in one, and the ticker goroutines
			// don't terminate until these goroutines stop
			if ui.QuitRequested {
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

		// Only display the progress bar if PSML is loading or if PDML is loading that is needed
		// by the UI. If the PDML is an optimistic load out of the display, then no need for
		// progress.
		doprog := false
		if ui.Loader.PsmlLoader.IsLoading() || (ui.Loader.PdmlLoader.IsLoading() && ui.Loader.PdmlLoader.LoadIsVisible()) {
			if prevProgPercentage >= 1.0 {
				if progCancelTimer != nil {
					progCancelTimer.Reset(time.Duration(500) * time.Millisecond)
					progCancelTimer = nil
				}
			} else {
				ui.SetProgressWidget(app)
				if progCancelTimer == nil {
					progCancelTimer = time.AfterFunc(time.Duration(100000)*time.Hour, func() {
						app.Run(gowid.RunFunction(func(app gowid.IApp) {
							ui.ClearProgressWidgetFor(app, ui.LoaderOwns)
							progCancelTimer = nil
						}))
					})
				}
			}

			tickChan = progTicker.C // progress is only enabled when a pcap may be loading

			// Rule:
			// - prefer progress if we can apply it to psml only (not pdml)
			// - otherwise use a spinner if interface load or fifo load in operation
			// - otherwise use progress for pdml
			if system.HaveFdinfo {
				// Prefer progress, if the OS supports it.
				doprog = true
				if ui.Loader.ReadingFromFifo() {
					// But if we are have an interface load (or a pipe load), then we can't
					// predict when the data will run out, so use a spinner. That's because we
					// feed the data to tshark -T psml with a tail command which reads from
					// the tmp file being created by the pipe/interface source.
					doprog = false
					if !ui.Loader.InterfaceLoader.IsLoading() && !ui.Loader.PsmlLoader.IsLoading() {
						// Unless those loads are finished, and the only loading activity is now
						// PDML/pcap, which is loaded on demand in blocks of 1000. Then we can
						// use the progress bar.
						doprog = true
					}
				}
			}
		}

		if ui.Loader.InterfaceLoader.IsLoading() && !currentlyInactive {
			inactivityChan = inactivityTimer.C
		}

		if !checkedPcapCache {
			checkPcapCacheChan = checkPcapCacheTimer.C
		}

		// Only process tcell and gowid events if the UI is running.
		if ui.Running {
			tcellEvents = app.TCellEvents
		}

		if ui.Fin != nil && ui.Fin.Active() {
			finChan = ui.Fin.C()
		}

		// For operations like ClearPcap - need previous loads to be fully finished first. The operations
		// channel is enabled until an operation starts, then disabled until the operation re-enables it
		// via a handler.
		//
		// Make sure state doesn't change until all handlers have been run
		if !ui.Loader.PdmlLoader.IsLoading() && !ui.Loader.PsmlLoader.IsLoading() {
			opsChan = pcap.OpsChan
		}

		afterRenderEvents = app.AfterRenderEvents

		wasLoadingPdmlLastTime = ui.Loader.PdmlLoader.IsLoading()
		wasLoadingAnythingLastTime = ui.Loader.LoadingAnything()

		select {

		case <-checkPcapCacheChan:
			// Only check the cache dir if we own it; don't want to delete pcap files
			// that might be shared with wireshark
			if profiles.ConfBool("main.use-tshark-temp-for-pcap-cache", false) {
				log.Infof("Termshark does not own the pcap temp dir %s; skipping size check", termshark.PcapDir())
			} else {
				termshark.PrunePcapCache()
			}
			checkedPcapCache = true

		case <-inactivityChan:
			if ui.Fin != nil {
				ui.Fin.Activate()
			}
			currentlyInactive = true

		case <-finChan:
			ui.Fin.Advance()
			app.Redraw()

		case <-ui.StartUIChan:
			log.Infof("Launching termshark UI")

			// Go to termshark UI view
			if err = app.ActivateScreen(); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting UI: %v\n", err)
				return 1
			}

			// Need to do that here because the app won't know how many colors the screen
			// has (and therefore which variant of the theme to load) until the screen is
			// activated.
			ui.ApplyCurrentTheme(app)

			// This needs to run after the toml config file is loaded.
			ui.SetupColors()

			// Start tcell/gowid events for keys, etc
			appRunner.Start()

			// Reinstate  our terminal overrides that allow ctrl-z
			if err := ctrlzLineDisc.Set(usetty); err != nil {
				ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
			}

			ui.Running = true
			startedSuccessfully = true

			ui.StartUIChan = nil // make sure it's not triggered again

			if runtime.GOOS != "windows" {
				if app.GetColorMode() == gowid.Mode8Colors {
					// If exists is true, it means we already tried and then reverted back, so
					// just load up termshark normally with no further interruption.
					if _, exists := os.LookupEnv("TERMSHARK_ORIGINAL_TERM"); !exists {
						if !profiles.ConfBool("main.disable-term-helper", false) {
							err = termshark.Does256ColorTermExist()
							if err != nil {
								log.Infof("Must use 8-color mode because 256-color version of TERM=%s unavailable - %v.", os.Getenv("TERM"), err)
							} else {
								time.AfterFunc(time.Duration(3)*time.Second, func() {
									app.Run(gowid.RunFunction(func(app gowid.IApp) {
										ui.SuggestSwitchingTerm(app)
									}))
								})
							}
						}
					}
				} else if os.Getenv("TERMSHARK_ORIGINAL_TERM") != "" {
					time.AfterFunc(time.Duration(3)*time.Second, func() {
						app.Run(gowid.RunFunction(func(app gowid.IApp) {
							ui.IsTerminalLegible(app)
						}))
					})
				}
			}

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

		case fn := <-opsChan:
			app.Run(fn)

		case <-ui.QuitRequestedChan:
			ui.QuitRequested = true
			// Without this, a quit during a pcap load won't happen until the load is finished
			if ui.Loader.LoadingAnything() {
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
					if err := ctrlzLineDisc.Set(usetty); err != nil {
						ui.OpenError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
					}

					ui.Running = true
					uiSuspended = false
				}
			} else if system.IsSigUSR1(sig) {
				if debug {
					termshark.ProfileCPUFor(20)
				} else {
					log.Infof("SIGUSR1 ignored by termshark - see the --debug flag")
				}

			} else if system.IsSigUSR2(sig) {
				if debug {
					termshark.ProfileHeap()
				} else {
					log.Infof("SIGUSR2 ignored by termshark - see the --debug flag")
				}

			} else {
				log.Infof("Starting termination via signal %v", sig)
				ui.RequestQuit()
			}

		case <-ui.CacheRequestsChan:
			ui.CacheRequests = pcap.ProcessPdmlRequests(ui.CacheRequests,
				ui.Loader.ParentLoader, ui.Loader.PdmlLoader, ui.SetStructWidgets{ui.Loader}, app)

		case <-tickChan:
			// We already know that we are LoadingPdml|LoadingPsml
			if doprog {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					prevProgPercentage = ui.UpdateProgressBarForFile(ui.Loader, prevProgPercentage, app)
				}))
			} else {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.UpdateProgressBarForInterface(ui.Loader.InterfaceLoader, app)
				}))
			}

		case ev := <-tcellEvents:
			app.HandleTCellEvent(ev, gowid.IgnoreUnhandledInput)
			inactivityTimer.Reset(inactiveDuration)
			currentlyInactive = false
			checkPcapCacheTimer.Reset(checkPcapCacheDuration)

		case ev, ok := <-afterRenderEvents:
			// This means app.Quit() has been called, which closes the AfterRenderEvents
			// channel - and then will accept no more events. select will then return
			// nil on this channel - which we then use to break the loop
			if !ok {
				break Loop
			}
			ev.RunThenRenderEvent(app)
			if ui.Running {
				app.RedrawTerminal()
			}

		case <-watcher.ConfigChanged():
			// Re-read so changes that can take effect immediately do so
			if err := profiles.ReadDefaultConfig(dirs[0].Path); err != nil {
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
