// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/gowid"
	"github.com/gcla/termshark"
	"github.com/gcla/termshark/cli"
	"github.com/gcla/termshark/pcap"
	"github.com/gcla/termshark/ui"
	"github.com/gcla/termshark/widgets/filter"
	"github.com/gdamore/tcell"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/fsnotify.v1"

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
	termshark.RegisterForSignals(sigChan)

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

	// These are needed because we need to distinguish from the flag being provided
	// and set off and the flag not being provided - in which case the config file
	// value is used.
	var darkModeSwitchSet bool   // whether switch was passed at command line
	var darkModeSwitch bool      // set via command line
	var autoScrollSwitchSet bool // whether switch was passed at command line
	var autoScrollSwitch bool    // set via command line

	// Termshark's own command line arguments. Used if we don't pass through to tshark.
	var opts cli.Termshark

	opts.DarkMode = func(val bool) {
		darkModeSwitch = val
		darkModeSwitchSet = true
	}
	opts.AutoScroll = func(val bool) {
		autoScrollSwitch = val
		autoScrollSwitchSet = true
	}

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

	usetty := cli.TtySwitchValue(&opts)
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

	var psrc pcap.IPacketSource

	pcapf := string(opts.Pcap)

	// If no interface specified, and no pcap specified via -r, then we assume the first
	// argument is a pcap file e.g. termshark foo.pcap
	if pcapf == "" && opts.Iface == "" {
		pcapf = string(opts.Args.FilterOrFile)
		// `termshark` => `termshark -i 1` (livecapture on default interface if no args)
		if pcapf == "" {
			psrc = pcap.InterfaceSource{Iface: "1"}
		}
	} else {
		// Add it to filter args. Figure out later if they're capture or display.
		filterArgs = append(filterArgs, opts.Args.FilterOrFile)
	}

	if pcapf != "" && opts.Iface != "" {
		fmt.Fprintf(os.Stderr, "Please supply either a pcap or an interface.\n")
		return 1
	}

	// Invariant: pcap != "" XOR opts.Iface != ""
	if psrc == nil {
		switch {
		case pcapf != "":
			psrc = pcap.FileSource{Filename: pcapf}
		case opts.Iface != "":
			psrc = pcap.InterfaceSource{Iface: opts.Iface}
		}
	}

	// go-flags returns [""] when no extra args are provided, so I can't just
	// test the length of this slice
	argsFilter := strings.Join(filterArgs, " ")

	// Work out capture filter afterwards because we need to determine first
	// whether any potential first argument is intended as a pcap file instead of
	// a capture filter.
	captureFilter := opts.CaptureFilter

	if psrc.IsInterface() && argsFilter != "" {
		if opts.CaptureFilter != "" {
			fmt.Fprintf(os.Stderr, "Two capture filters provided - '%s' and '%s' - please supply one only.\n", opts.CaptureFilter, argsFilter)
			return 1
		}
		captureFilter = argsFilter
	}

	displayFilter := opts.DisplayFilter

	// Validate supplied filters e.g. no capture filter when reading from file
	if psrc.IsFile() {
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

	// - means read from stdin. But termshark uses stdin for interacting with the UI. So if the
	// iface is -, then dup stdin to a free descriptor, adjust iface to read from that descriptor,
	// then open /dev/tty on stdin.
	newinputfd := -1

	if psrc.Name() == "-" {
		if termshark.IsTerminal(os.Stdin.Fd()) {
			fmt.Fprintf(os.Stderr, "Requested pcap source is %v (\"stdin\") but stdin is a tty.\n", opts.Iface)
			fmt.Fprintf(os.Stderr, "Perhaps you intended to pipe packet input to termshark?\n")
			return 1
		}
		if runtime.GOOS != "windows" {
			newinputfd, err = termshark.MoveStdin()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				return 1
			}
			defer func() {
				termshark.CloseDescriptor(newinputfd)
			}()
			psrc = pcap.PipeSource{Descriptor: fmt.Sprintf("/dev/fd/%d", newinputfd)}
		} else {
			fmt.Fprintf(os.Stderr, "Sorry, termshark does not yet support piped input on Windows.\n")
			return 1
		}
	}

	// Better to do a command-line error if file supplied at command-line is not found. File
	// won't be "-" at this point because above we switch to -i if input is "-"

	// We haven't distinguished between file sources and fifo sources yet. So IsFile() will be true
	// even if argument is a fifo
	if psrc.IsFile() {
		stat, err := os.Stat(psrc.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v.\n", psrc.Name(), err)
			return 1
		}
		if stat.Mode()&os.ModeNamedPipe != 0 {
			// If termshark was invoked with -r myfifo, switch to -i myfifo, which tshark uses. This
			// also puts termshark in "interface" mode where it assumes the source is unbounded
			// (e.g. a different spinner)
			psrc = pcap.FifoSource{Filename: psrc.Name()}
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

	// Here we now have an accurate view of psrc - either file, fifo, pipe or interface

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

	for _, dir := range []string{termshark.CacheDir(), termshark.PcapDir()} {
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, 0777)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unexpected error making dir %s: %v", dir, err)
				return 1
			}
		}
	}

	emptyPcap := termshark.CacheFile("empty.pcap")
	if _, err := os.Stat(emptyPcap); os.IsNotExist(err) {
		err = termshark.WriteEmptyPcap(emptyPcap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create dummy pcap %s: %v", emptyPcap, err)
			return 1
		}
	}

	// If opts.Iface is provided as a number, it's meant as the index of the interfaces as
	// per the order returned by the OS. useIface will always be the name of the interface.

	// See if the interface argument is an integer
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
		ifaces, err := termshark.Interfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not enumerate network interfaces: %v\n", err)
			return 1
		}

		gotit := false
		for i, n := range ifaces {
			if i == psrc.Name() || n == ifaceIdx {
				gotit = true
				break
			}
		}
		if !gotit {
			fmt.Fprintf(os.Stderr, "Could not find network interface %s\n", psrc.Name())
			return 1
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
		if (psrc.IsInterface() || psrc.IsFifo() || psrc.IsPipe()) && startedSuccessfully {
			fmt.Printf("Packets read from %s have been saved in %s\n", psrc.Name(), ifacePcapFilename)
		}
	}()

	//======================================================================

	ifaceExitCode := 0
	var ifaceErr error

	// This is deferred until after the app is Closed - otherwise messages written to stdout/stderr are
	// swallowed by tcell.
	defer func() {
		if ifaceExitCode != 0 {
			fmt.Fprintf(os.Stderr, "Cannot capture on device %s", psrc.Name())
			if ifaceErr != nil {
				fmt.Fprintf(os.Stderr, ": %v", ifaceErr)
			}
			fmt.Fprintf(os.Stderr, " (exit code %d)\n", ifaceExitCode)
			fmt.Fprintf(os.Stderr, "See https://wiki.wireshark.org/CaptureSetup/CapturePrivileges for more info.\n")
		}
	}()

	// Initialize application state for dark mode
	if darkModeSwitchSet {
		ui.DarkMode = darkModeSwitch
	} else {
		ui.DarkMode = termshark.ConfBool("main.dark-mode")
	}

	// Initialize application state for auto-scroll
	if autoScrollSwitchSet {
		ui.AutoScroll = autoScrollSwitch
	} else {
		ui.AutoScroll = termshark.ConfBool("main.auto-scroll")
	}

	// Set them up here so they have access to any command-line flags that
	// need to be passed to the tshark commands used
	pdmlArgs := termshark.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs := termshark.ConfStringSlice("main.psml-args", []string{})
	tsharkArgs := termshark.ConfStringSlice("main.tshark-args", []string{})
	cacheSize := termshark.ConfInt("main.pcap-cache-size", 64)
	bundleSize := termshark.ConfInt("main.pcap-bundle-size", 1000)
	if bundleSize <= 0 {
		maxBundleSize := 100000
		log.Infof("Config specifies pcap-bundle-size as %d - setting to max (%d)", bundleSize, maxBundleSize)
		bundleSize = maxBundleSize
	}
	ui.PcapScheduler = pcap.NewScheduler(
		pcap.MakeCommands(opts.DecodeAs, tsharkArgs, pdmlArgs, psmlArgs),
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

	if psrc.IsInterface() || psrc.IsFifo() || psrc.IsPipe() {
		ifaceTmpFile = pcap.TempPcapFile(psrc.Name())

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
		// dumpcap -i - -w ~/.cache/pcaps/tmp123.pcap
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
		if cerr, ok := termshark.RootCause(err).(*exec.Error); ok {
			if cerr.Err.Error() == exec.ErrNotFound.Error() {
				fmt.Fprintf(os.Stderr, "Termshark could not recognize your terminal. Try changing $TERM.\n")
			}
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

	if psrc.IsFile() {
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
	} else if psrc.IsInterface() || psrc.IsFifo() || psrc.IsPipe() {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		ifaceExitCode = 0
		//if ifaceExitCode, ifaceErr = termshark.RunForExitCode("dumpcap", "-i", useIface, "-a", "duration:1", "-w", os.DevNull); ifaceExitCode != 0 {
		//return 1
		//}

		ifValid := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.FilterWidget.SetValue(displayFilter, app)
			}))
			ifacePcapFilename = ifaceTmpFile
			ui.PcapScheduler.RequestLoadInterface(psrc, captureFilter, displayFilter, ifaceTmpFile,
				ui.SaveRecents{
					UpdatePacketViews: ui.MakePacketViewUpdater(app),
					Pcap:              "",
					Filter:            displayFilter,
				})
		}
		validator.Valid = &filter.ValidateCB{Fn: ifValid, App: app}
		validator.Validate(displayFilter)
	}

	quitRequested := false
	prevstate := ui.Loader.State()
	var prev float64

	progTicker := time.NewTicker(time.Duration(200) * time.Millisecond)

	loaderPsmlFinChan := ui.Loader.PsmlFinishedChan
	loaderIfaceFinChan := ui.Loader.IfaceFinishedChan
	loaderPdmlFinChan := ui.Loader.Stage2FinishedChan

	ctrlzLineDisc := termshark.TerminalSignals{}

Loop:
	for {
		var opsChan <-chan pcap.RunFn
		var tickChan <-chan time.Time
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
			if ui.Loader.State() != prevstate {
				// If the state is now 0, it means no interface-reading process is running. That means
				// we will no longer be reading from an interface or a fifo, so we point the loader at
				// the file we wrote to the cache, and redirect all loads/filters to that now.
				ui.Loader.TurnOffPipe()
				if quitRequested {
					app.Quit()
				}
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					ui.ClearProgressWidget(app)
					ui.SetProgressDeterminate(app) // always switch back - for pdml (partial) loads of later data.
				}))
				// When the progress bar is enabled, track the previous percentage reached. This
				// is so that I don't go "backwards" if I generate a progress value less than the last
				// one, using the current algorithm (because it would be confusing to see it go backwards)
				prev = 0.0
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

		afterRenderEvents = app.AfterRenderEvents

		prevstate = ui.Loader.State()

		select {

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
				ui.Loader.Close()

				appRunner.Stop()
				app.Close()
				ui.Running = false
			}()

		case <-ui.QuitRequestedChan:
			if ui.Loader.State() == 0 {

				// Only explicitly quit if this flag isn't set because if it is set, then the quit
				// will happen before the select{} statement above
				if !quitRequested {
					app.Quit()
				}

				// If the UI isn't running, then there aren't app events, and that channel is used
				// to break the select loop. So break it manually.
				if !ui.Running {
					break Loop
				}
			} else {
				quitRequested = true
				// We know we're not idle, so stop any load so the quit op happens quickly for the user. Quit
				// will happen next time round because the quitRequested flag is checked.
				ui.PcapScheduler.RequestStopLoad(ui.NoHandlers{})
			}

		case sig := <-sigChan:
			if termshark.IsSigTSTP(sig) {
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
				if err := termshark.StopMyself(); err != nil {
					fmt.Fprintf(os.Stderr, "Unexpected error issuing SIGSTOP: %v\n", err)
					return 1
				}

			} else if termshark.IsSigCont(sig) {
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
			} else if termshark.IsSigUSR1(sig) {
				if cli.FlagIsTrue(opts.Debug) {
					termshark.ProfileCPUFor(20)
				} else {
					log.Infof("SIGUSR1 ignored by termshark - see the --debug flag")
				}

			} else if termshark.IsSigUSR2(sig) {
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
			if termshark.HaveFdinfo && (ui.Loader.State() == pcap.LoadingPdml || !ui.Loader.ReadingFromFifo()) {
				prev = ui.UpdateProgressBarForFile(ui.Loader, prev, app)
			} else {
				ui.UpdateProgressBarForInterface(ui.Loader, app)
			}

		case <-emptyStructViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.SetStructViewMissing(app)
				ui.EmptyStructViewTimer = nil
			}))

		case <-emptyHexViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ui.SetHexViewMissing(app)
				ui.EmptyHexViewTimer = nil
			}))

		case ev := <-tcellEvents:
			app.HandleTCellEvent(ev, gowid.IgnoreUnhandledInput)

		case ev, ok := <-afterRenderEvents:
			// This means app.Quit() has been called, which closes the AfterRenderEvents
			// channel - and then will accept no more events. select will then return
			// nil on this channel - which we then use to break the loop
			if !ok {
				break Loop
			}
			app.RunThenRenderEvent(ev)

		case <-watcher.ConfigChanged():
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
