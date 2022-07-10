// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/format"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

//======================================================================

var PcapCmds ILoaderCmds
var PcapOpts Options

var OpsChan chan gowid.RunFunction

func init() {
	OpsChan = make(chan gowid.RunFunction, 100)
}

//======================================================================

var Goroutinewg *sync.WaitGroup

type RunFn func()

//======================================================================

type LoaderState bool

const (
	NotLoading LoaderState = false
	Loading    LoaderState = true
)

func (t LoaderState) String() string {
	if t {
		return "loading"
	} else {
		return "not-loading"
	}
}

//======================================================================

type ProcessState int

const (
	NotStarted ProcessState = 0
	Started    ProcessState = 1
	Terminated ProcessState = 2
)

func (p ProcessState) String() string {
	switch p {
	case NotStarted:
		return "NotStarted"
	case Started:
		return "Started"
	case Terminated:
		return "Terminated"
	default:
		return "Unknown"
	}
}

//======================================================================

type IBasicCommand interface {
	fmt.Stringer
	Start() error
	Wait() error
	Pid() int
	Kill() error
	StderrSummary() []string
}

func MakeUsefulError(cmd IBasicCommand, err error) gowid.KeyValueError {
	return gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
		"command": cmd.String(),
		"error":   err,
		"stderr":  strings.Join(cmd.StderrSummary(), "\n"),
	})
}

type ITailCommand interface {
	IBasicCommand
	SetStdout(io.Writer) // set to the write side of a fifo, for example - the command will .Write() here
	Close() error        // closes stdout, which signals tshark -T psml
}

type IPcapCommand interface {
	IBasicCommand
	StdoutReader() (io.ReadCloser, error) // termshark will .Read() from result
}

type ILoaderCmds interface {
	Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand
	Tail(tmpfile string) ITailCommand
	Psml(pcap interface{}, displayFilter string) IPcapCommand
	Pcap(pcap string, displayFilter string) IPcapCommand
	Pdml(pcap string, displayFilter string) IPcapCommand
}

//======================================================================

// PacketLoader supports swapping out loaders
type PacketLoader struct {
	*ParentLoader
}

// Renew is called when a new pcap is loaded from an open termshark session i.e. termshark
// was started with one packet source, then a new one is selected. This ensures that all
// connected loaders that might still be doing work are cancelled.
func (c *PacketLoader) Renew() {
	if c.ParentLoader != nil {
		c.ParentLoader.CloseMain()
	}
	c.ParentLoader = NewPcapLoader(c.ParentLoader.cmds, c.runner, c.ParentLoader.opt)
}

type ParentLoader struct {
	// Note that a nil InterfaceLoader implies this loader is not handling a "live" packet source
	*InterfaceLoader // these are only replaced from the main goroutine, so no lock needed
	*PsmlLoader
	*PdmlLoader

	cmds ILoaderCmds

	tailStoppedDeliberately bool // true if tail is stopped because its packet feed has run out

	psrcs         []IPacketSource // The canonical struct for the loader's current packet source.
	displayFilter string
	captureFilter string

	ifaceFile string // shared between InterfaceLoader and PsmlLoader - to preserve and feed packets

	mainCtx      context.Context // cancelling this cancels the dependent contexts - used to close whole loader.
	mainCancelFn context.CancelFunc

	loadWasCancelled bool // True if the last load (iface or file) was halted by the stop button or ctrl-c

	runner IMainRunner
	opt    Options // held only to pass to the PDML and PSML loaders when renewed
}

type InterfaceLoader struct {
	state LoaderState

	ifaceCtx      context.Context // cancels the iface reader process
	ifaceCancelFn context.CancelFunc

	ifaceCmd IBasicCommand

	sync.Mutex
	// set by the iface procedure when it has finished e.g. the pipe to the fifo has finished, the
	// iface process has been killed, etc. This tells the psml-reading procedure when it should stop i.e.
	// when this many bytes have passed through.
	totalFifoBytesWritten gwutil.Int64Option
	totalFifoBytesRead    gwutil.Int64Option
	fifoError             error
}

type PsmlLoader struct {
	state LoaderState // which pieces are currently loading

	PcapPsml interface{} // Pcap file source for the psml reader - fifo if iface+!stopped; tmpfile if iface+stopped; pcap otherwise

	psmlStoppedDeliberately_ bool // true if loader is in a transient state due to a user operation e.g. stop, reload, etc

	psmlCtx      context.Context // cancels the psml loading process
	psmlCancelFn context.CancelFunc
	tailCtx      context.Context // cancels the tail reader process (if iface in operation)
	tailCancelFn context.CancelFunc

	// Signalled when the psml is fully loaded (or already loaded) - to tell
	// the pdml and pcap reader goroutines to start - they can then map table
	// row -> frame number
	startStage2Chan chan struct{}

	PsmlFinishedChan chan struct{} // closed when entire psml load process is done

	tailCmd ITailCommand
	PsmlCmd IPcapCommand // gcla later todo - change to pid like PdmlPid

	sync.Mutex
	packetAverageLength []averageTracker // length of num columns
	packetMaxLength     []maxTracker     // length of num columns
	packetPsmlData      [][]string
	packetPsmlColors    []PacketColors
	packetPsmlHeaders   []string
	PacketNumberMap     map[int]int // map from actual packet row <packet>12</packet> to pos in unsorted table
	// This would be affected by a display filter e.g. packet 12 might be the 1st packet in the table.
	// I need this so that if the user jumps to a mark stored as "packet 12", I can find the right table row.
	PacketNumberOrder map[int]int // e.g. {12->44, 44->71, 71->72,...} - the packet numbers, in order, affected by a filter.
	// If I use a generic ordered map, I could avoid this separate structure

	PacketCache *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)] - accessed from any goroutine

	opt Options
}

type PdmlLoader struct {
	state LoaderState // which pieces are currently loading

	PcapPdml string // Pcap file source for the pdml reader - tmpfile if iface; pcap otherwise
	PcapPcap string // Pcap file source for the pcap reader - tmpfile if iface; pcap otherwise

	pdmlStoppedDeliberately_ bool // true if loader is in a transient state due to a user operation e.g. stop, reload, etc

	stage2Ctx      context.Context // cancels the pcap/pdml loading process
	stage2CancelFn context.CancelFunc

	stage2Wg sync.WaitGroup

	startChan chan struct{}

	Stage2FinishedChan chan struct{} // closed when entire pdml+pcap load process is done

	PdmlPid int // 0 if process not started
	PcapPid int // 0 if process not started

	sync.Mutex
	visible                  bool // true if this pdml load is needed right now by the UI
	rowCurrentlyLoading      int  // set by the pdml loading stage - main goroutine only
	highestCachedRow         int  // main goroutine only
	KillAfterReadingThisMany int  // A shortcut - tell pcap/pdml to read one - no lock worked out yet

	opt Options
}

type PacketColors struct {
	FG gowid.IColor
	BG gowid.IColor
}

type Options struct {
	CacheSize      int
	PacketsPerLoad int
}

type iLoaderEnv interface {
	Commands() ILoaderCmds
	MainRun(fn gowid.RunFunction)
	Context() context.Context
}

type iPsmlLoaderEnv interface {
	iLoaderEnv
	iTailCommand
	PsmlStoppedDeliberately() bool
	TailStoppedDeliberately() bool
	LoadWasCancelled() bool
	DisplayFilter() string
	InterfaceFile() string
	PacketSources() []IPacketSource
}

// IMainRunner is implemented by a type that runs a closure on termshark's main loop
// (via gowid's App.Run)
type IMainRunner interface {
	Run(fn gowid.RunFunction)
}

type Runner struct {
	gowid.IApp
}

var _ IMainRunner = (*Runner)(nil)

func (a *Runner) Run(fn gowid.RunFunction) {
	a.IApp.Run(fn)
}

//======================================================================

func NewPcapLoader(cmds ILoaderCmds, runner IMainRunner, opts ...Options) *ParentLoader {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.CacheSize == 0 {
		opt.CacheSize = 32
	}
	if opt.PacketsPerLoad == 0 {
		opt.PacketsPerLoad = 1000 // default
	} else if opt.PacketsPerLoad < 100 {
		opt.PacketsPerLoad = 100 // minimum
	}

	res := &ParentLoader{
		PsmlLoader: &PsmlLoader{}, // so default fields are set and XmlLoader is not nil
		PdmlLoader: &PdmlLoader{
			opt: opt,
		},
		cmds:   cmds,
		runner: runner,
		opt:    opt,
	}

	res.mainCtx, res.mainCancelFn = context.WithCancel(context.Background())

	res.RenewPsmlLoader()
	res.RenewPdmlLoader()

	return res
}

func (c *ParentLoader) RenewPsmlLoader() {
	c.PsmlLoader = &PsmlLoader{
		PcapPsml:            c.PsmlLoader.PcapPsml,
		tailCmd:             c.PsmlLoader.tailCmd,
		PsmlCmd:             c.PsmlLoader.PsmlCmd,
		packetAverageLength: make([]averageTracker, 64),
		packetMaxLength:     make([]maxTracker, 64),
		packetPsmlData:      make([][]string, 0),
		packetPsmlColors:    make([]PacketColors, 0),
		packetPsmlHeaders:   make([]string, 0, 10),
		PacketNumberMap:     make(map[int]int),
		PacketNumberOrder:   make(map[int]int),
		startStage2Chan:     make(chan struct{}), // do this before signalling start
		PsmlFinishedChan:    make(chan struct{}),
		opt:                 c.opt,
	}
	packetCache, err := lru.New(c.opt.CacheSize)
	if err != nil {
		log.Fatal(err)
	}
	c.PacketCache = packetCache
}

func (c *ParentLoader) RenewPdmlLoader() {
	c.PdmlLoader = &PdmlLoader{
		PcapPdml:            c.PcapPdml,
		PcapPcap:            c.PcapPcap,
		rowCurrentlyLoading: -1,
		highestCachedRow:    -1,
		opt:                 c.opt,
	}
}

func (c *ParentLoader) RenewIfaceLoader() {
	c.InterfaceLoader = &InterfaceLoader{}
}

func (p *ParentLoader) LoadingAnything() bool {
	return p.PsmlLoader.IsLoading() || p.PdmlLoader.IsLoading() || p.InterfaceLoader.IsLoading()
}

func (p *ParentLoader) InterfaceFile() string {
	return p.ifaceFile
}

func (p *ParentLoader) DisplayFilter() string {
	return p.displayFilter
}

func (p *ParentLoader) CaptureFilter() string {
	return p.captureFilter
}

func (p *ParentLoader) TurnOffPipe() {
	// Switch over to  the temp pcap file. If a new filter is applied
	// after stopping, we should read from the temp file and not the fifo
	// because nothing will be feeding the fifo.
	if p.PsmlLoader.PcapPsml != p.PdmlLoader.PcapPdml {
		log.Infof("Switching from interface/fifo mode to file mode")
		p.PsmlLoader.PcapPsml = p.PdmlLoader.PcapPdml
	}
}

func (p *ParentLoader) PacketSources() []IPacketSource {
	return p.psrcs
}

func (p *ParentLoader) PsmlStoppedDeliberately() bool {
	return p.psmlStoppedDeliberately_
}

func (p *ParentLoader) TailStoppedDeliberately() bool {
	return p.tailStoppedDeliberately
}

func (p *ParentLoader) LoadWasCancelled() bool {
	return p.loadWasCancelled
}

func (p *ParentLoader) Commands() ILoaderCmds {
	return p.cmds
}

func (p *ParentLoader) Context() context.Context {
	return p.mainCtx
}

func (p *ParentLoader) MainRun(fn gowid.RunFunction) {
	p.runner.Run(fn)
}

// CloseMain shuts down the whole loader, including progress monitoring goroutines. Use this only
// when about to load a new pcap (use a new loader)
func (c *ParentLoader) CloseMain() {
	c.psmlStoppedDeliberately_ = true
	c.pdmlStoppedDeliberately_ = true
	if c.mainCancelFn != nil {
		c.mainCancelFn()
		c.mainCancelFn = nil
	}
}

func (c *ParentLoader) StopLoadPsmlAndIface(cb interface{}) {
	log.Infof("Requested stop psml + iface")

	c.psmlStoppedDeliberately_ = true
	c.loadWasCancelled = true

	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadIface()
}

//======================================================================

func (c *PacketLoader) Reload(filter string, cb interface{}, app gowid.IApp) {
	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadPdml()

	OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
		c.RenewPsmlLoader()
		c.RenewPdmlLoader()

		// This is not ideal. I'm clearing the views, but I'm about to
		// restart. It's not really a new source, so called the new source
		// handler is an untidy way of updating the current capture in the
		// title bar again
		handleClear(NoneCode, app, cb)

		c.displayFilter = filter

		log.Infof("Applying display filter '%s'", filter)

		c.loadPsmlSync(c.InterfaceLoader, c, cb, app)
	})
}

func (c *PacketLoader) LoadPcap(pcap string, displayFilter string, cb interface{}, app gowid.IApp) {
	log.Infof("Requested pcap file load for '%v'", pcap)

	curDisplayFilter := displayFilter
	// The channel is unbuffered, and monitored from the same goroutine, so this would block
	// unless we start a new goroutine

	if c.Pcap() == pcap && c.DisplayFilter() == curDisplayFilter {
		log.Infof("No operation - same pcap and filter.")
		HandleError(NoneCode, app, fmt.Errorf("Same pcap and filter - nothing to do."), cb)
	} else {

		c.stopTail()
		c.stopLoadPsml()
		c.stopLoadPdml()
		c.stopLoadIface()

		OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
			c.Renew()

			// This will enable the operation when clear completes
			handleClear(NoneCode, app, cb)

			c.psrcs = []IPacketSource{FileSource{Filename: pcap}}
			c.ifaceFile = ""

			c.PcapPsml = pcap
			c.PcapPdml = pcap
			c.PcapPcap = pcap
			c.displayFilter = displayFilter

			// call from main goroutine - when new filename is established
			handleNewSource(NoneCode, app, cb)

			log.Infof("Starting new pcap file load '%s'", pcap)
			c.loadPsmlSync(nil, c.ParentLoader, cb, app)
		})
	}
}

// Clears the currently loaded data. If the loader is currently reading from an
// interface, the loading continues after the current data has been discarded. If
// the loader is currently reading from a file, the loading *stops*.

// Intended to restart iface loader - since a clear will discard all data up to here.
func (c *PacketLoader) ClearPcap(cb interface{}) {
	startIfaceAgain := false

	if c.InterfaceLoader != nil {
		// Don't restart if the previous interface load was deliberately cancelled
		if !c.loadWasCancelled {
			startIfaceAgain = true
			for _, psrc := range c.psrcs {
				startIfaceAgain = startIfaceAgain && CanRestart(psrc) // Only try to restart if the packet source allows
			}
		}
		c.stopLoadIface()
	}

	// Don't close main context, it's used by interface process.
	// We may not have anything running, but it's ok - then the op channel
	// will be enabled
	if !startIfaceAgain {
		c.loadWasCancelled = true
	}
	c.stopTail()
	c.stopLoadPsml()
	c.stopLoadPdml()

	// When stop is done, launch the clear and restart
	OpsChan <- gowid.RunFunction(func(app gowid.IApp) {
		// Don't CloseMain - that will stop the interface process too
		c.loadWasCancelled = false
		c.RenewPsmlLoader()
		c.RenewPdmlLoader()

		handleClear(NoneCode, app, cb)

		if !startIfaceAgain {
			c.psrcs = c.psrcs[:0]
			c.ifaceFile = ""
			c.PcapPsml = ""
			c.PcapPdml = ""
			c.PcapPcap = ""
			c.displayFilter = ""
		} else {
			c.RenewIfaceLoader()

			if err := c.loadInterfaces(c.psrcs, c.CaptureFilter(), c.DisplayFilter(), c.InterfaceFile(), cb, app); err != nil {
				HandleError(NoneCode, app, err, cb)
			}
		}
	})
}

// Always called from app goroutine context - so don't need to protect for race on cancelfn
// Assumes gstate is ready
// iface can be a number, or a fifo, or a pipe...
func (c *PacketLoader) LoadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}, app gowid.IApp) error {
	c.RenewIfaceLoader()

	return c.loadInterfaces(psrcs, captureFilter, displayFilter, tmpfile, cb, app)
}

func (c *ParentLoader) loadPsmlForInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}, app gowid.IApp) error {
	// It's a temporary unique file, and no processes are started yet, so either
	// (a) it doesn't exist, OR
	// (b) it does exist in which case this load is a result of a restart.
	// In ths second case, we need to discard existing packets before starting
	// tail in case it catches this file with existing data.
	err := os.Remove(tmpfile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	c.PcapPsml = nil
	c.PcapPdml = tmpfile
	c.PcapPcap = tmpfile

	c.psrcs = psrcs // dpm't know if it's fifo (tfifo), pipe (/dev/fd/3) or iface (eth0). Treated same way

	c.ifaceFile = tmpfile
	c.displayFilter = displayFilter
	c.captureFilter = captureFilter

	handleNewSource(NoneCode, app, cb)

	log.Infof("Starting new interface/fifo load '%v'", SourcesString(psrcs))
	c.PsmlLoader.loadPsmlSync(c.InterfaceLoader, c, cb, app)

	return nil
}

// intended for internal use
func (c *ParentLoader) loadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}, app gowid.IApp) error {

	if err := c.loadPsmlForInterfaces(psrcs, captureFilter, displayFilter, tmpfile, cb, app); err != nil {
		return err
	}

	// Deliberately use only HandleEnd handler once, in the PSML load - when it finishes,
	// we'll reenable ops
	c.InterfaceLoader.loadIfacesSync(c, cb, app)

	return nil
}

func (c *ParentLoader) String() string {
	names := make([]string, 0, len(c.psrcs))
	for _, psrc := range c.psrcs {
		switch {
		case psrc.IsFile() || psrc.IsFifo():
			names = append(names, filepath.Base(psrc.Name()))
		case psrc.IsPipe():
			names = append(names, "<stdin>")
		case psrc.IsInterface():
			names = append(names, psrc.Name())
		default:
			names = append(names, "(no packet source)")
		}
	}
	return strings.Join(names, " + ")
}

func (c *ParentLoader) Empty() bool {
	return len(c.psrcs) == 0
}

func (c *ParentLoader) Pcap() string {
	for _, psrc := range c.psrcs {
		if psrc != nil && psrc.IsFile() {
			return psrc.Name()
		}
	}
	return ""
}

func (c *ParentLoader) Interfaces() []string {
	names := make([]string, 0, len(c.psrcs))
	for _, psrc := range c.psrcs {
		if psrc != nil && !psrc.IsFile() {
			names = append(names, psrc.Name())
		}
	}
	return names
}

func (c *ParentLoader) loadIsNecessary(ev LoadPcapSlice) bool {
	res := true
	if ev.Row > c.NumLoaded() {
		res = false
	} else if ce, ok := c.CacheAt((ev.Row / c.opt.PacketsPerLoad) * c.opt.PacketsPerLoad); ok && ce.Complete() {
		// Might be less because a cache load might've been interrupted - if it's not truncated then
		// we're set
		res = false

		// I can't conclude that a load based at row 0 is sufficient to ignore this one.
		// The previous load might've started when only 10 packets were available (via the
		// the PSML data), so the PDML end idx would be frame.number < 10. This load might
		// be for a rocus position of 20, which would map via rounding to row 0. But we
		// don't have the data.

		// Hang on - this is for a load that has finished. If it was a live load, the cache
		// will not be marked complete for this batch of data - so a live load that is loading
		// this batch, but started earlier in the load (so frame.number < X where X < row)
		// will not be marked complete in the cache, so the load will be redone if needed. If
		// we get here, the load is still underway, so let it complete.
	} else if c.LoadingRow() == ev.Row {
		res = false
	}
	return res
}

//======================================================================

// Holds a reference to the loader, and wraps Read() around the tail process's
// Read(). Count the bytes, and when they are equal to the final total of bytes
// written by the tshark -i process (spooling to a tmp file), a function is called
// which stops the PSML process.
type tailReadTracker struct {
	tailReader io.Reader
	loader     *InterfaceLoader
	tail       iTailCommand
	callback   interface{}
	app        gowid.IApp
}

func (r *tailReadTracker) Read(p []byte) (int, error) {
	n, err := r.tailReader.Read(p)

	r.loader.Lock()
	if r.loader.totalFifoBytesRead.IsNone() {
		r.loader.totalFifoBytesRead = gwutil.SomeInt64(int64(n))
	} else {
		r.loader.totalFifoBytesRead = gwutil.SomeInt64(int64(n) + r.loader.totalFifoBytesRead.Val())
	}
	// err == ErrClosed if the pipe (tailReader) that is wrapped in this tracker is closed.
	// This can happen because this call to Read() and the deferred closepipe() function run
	// at the same time.
	if err != nil && r.loader.fifoError == nil && err != io.EOF && !errIsAlreadyClosed(err) {
		r.loader.fifoError = err
	}
	r.loader.Unlock()

	r.loader.checkAllBytesRead(r.tail, r.callback, r.app)

	return n, err
}

func errIsAlreadyClosed(err error) bool {
	if err == os.ErrClosed {
		return true
	} else if err, ok := err.(*os.PathError); ok {
		return errIsAlreadyClosed(err.Err)
	} else {
		return false
	}
}

//======================================================================

type iPdmlLoaderEnv interface {
	iLoaderEnv
	DisplayFilter() string
	ReadingFromFifo() bool
	StartStage2ChanFn() chan struct{}
	PacketCacheFn() *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)]
	updateCacheEntryWithPdml(row int, pdml []IPdmlPacket, done bool)
	updateCacheEntryWithPcap(row int, pcap [][]byte, done bool)
	LengthOfPdmlCacheEntry(row int) (int, error)
	LengthOfPcapCacheEntry(row int) (int, error)
	CacheAt(row int) (CacheEntry, bool)
	DoWithPsmlData(func([][]string))
}

func (c *PdmlLoader) loadPcapSync(row int, visible bool, ps iPdmlLoaderEnv, cb interface{}, app gowid.IApp) {

	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	c.stage2Ctx, c.stage2CancelFn = context.WithCancel(ps.Context())

	c.state = Loading
	c.rowCurrentlyLoading = row
	c.visible = visible

	// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
	var pdmlCancelled int32
	var pcapCancelled int32
	c.startChan = make(chan struct{})

	c.Stage2FinishedChan = make(chan struct{}) // gcla later todo - suspect

	// Returns true if it's an error we should bring to user's attention
	unexpectedPdmlError := func(err error) bool {
		cancelled := atomic.LoadInt32(&pdmlCancelled)
		if cancelled == 0 {
			if err != io.EOF {
				if err, ok := err.(*xml.SyntaxError); !ok || err.Msg != "unexpected EOF" {
					return true
				}
			}
		}
		return false
	}

	unexpectedPcapError := func(err error) bool {
		cancelled := atomic.LoadInt32(&pcapCancelled)
		if cancelled == 0 {
			if err != io.EOF {
				if err, ok := err.(*xml.SyntaxError); !ok || err.Msg != "unexpected EOF" {
					return true
				}
			}
		}
		return false
	}

	setPcapCancelled := func() {
		atomic.CompareAndSwapInt32(&pcapCancelled, 0, 1)
	}

	setPdmlCancelled := func() {
		atomic.CompareAndSwapInt32(&pdmlCancelled, 0, 1)
	}

	//======================================================================

	var displayFilterStr string

	sidx := -1
	eidx := -1

	// Determine this in main goroutine
	termshark.TrackedGo(func() {

		ps.MainRun(gowid.RunFunction(func(app gowid.IApp) {
			HandleBegin(PdmlCode, app, cb)
		}))

		// This should correctly wait for all resources, no matter where in the process of creating them
		// an interruption or error occurs
		defer func(p *PdmlLoader) {
			// Wait for all other goroutines to complete
			p.stage2Wg.Wait()

			// The process Wait() goroutine will always expect a stage2 cancel at some point. It can
			// come early, if the user interrupts the load. If not, then we send it now, to let
			// that goroutine terminate.
			p.stage2CancelFn()

			ps.MainRun(gowid.RunFunction(func(app gowid.IApp) {
				close(p.Stage2FinishedChan)
				HandleEnd(PdmlCode, app, cb)

				p.state = NotLoading
				p.rowCurrentlyLoading = -1
				p.stage2CancelFn = nil
			}))
		}(c)

		// Set these before starting the pcap and pdml process goroutines so that
		// at the beginning, PdmlCmd and PcapCmd are definitely not nil. These
		// values are saved by the goroutine, and used to access the pid of these
		// processes, if they are started.
		var pdmlCmd IPcapCommand
		var pcapCmd IPcapCommand

		//
		// Goroutine to set mapping between table rows and frame numbers
		//
		termshark.TrackedGo(func() {
			select {
			case <-ps.StartStage2ChanFn():
				break
			case <-c.stage2Ctx.Done():
				return
			}

			// Do this - but if we're cancelled first (stage2Ctx.Done), then they
			// don't need to be signalled because the other selects waiting on these
			// channels will be cancelled too.
			// This has to wait until the PsmlCmd and PcapCmd are set - because next stages depend
			// on those
			defer func() {
				// Signal the pdml and pcap reader to start.
				select {
				case <-c.startChan: // it will be closed if the psml has loaded already, and this e.g. a cached load
				default:
					close(c.startChan)
				}
			}()

			// If there's no filter, psml, pdml and pcap run concurrently for speed. Therefore the pdml and pcap
			// don't know how large the psml will be. So we set numToRead to 1000. This might be too high, but
			// we only use this to determine when we can kill the reading processes early. The result will be
			// correct if we don't kill the processes, it just might load for longer.
			c.KillAfterReadingThisMany = c.opt.PacketsPerLoad
			var err error
			if ps.DisplayFilter() == "" {
				sidx = row + 1
				// +1 for frame.number being 1-based; +1 to read past the end so that
				// the XML decoder doesn't stall and I can kill after abcdex
				eidx = row + c.opt.PacketsPerLoad + 1 + 1
			} else {
				ps.DoWithPsmlData(func(psmlData [][]string) {
					if len(psmlData) > row {
						sidx, err = strconv.Atoi(psmlData[row][0])
						if err != nil {
							log.Fatal(err)
						}
						if len(psmlData) > row+c.opt.PacketsPerLoad+1 {
							// If we have enough packets to request one more than the amount to
							// cache, then requesting one more will mean the XML decoder won't
							// block at packet 999 waiting for </pdml> - so this is a hack to
							// let me promptly kill tshark when I've read enough.
							eidx, err = strconv.Atoi(psmlData[row+c.opt.PacketsPerLoad+1][0])
							if err != nil {
								log.Fatal(err)
							}
						} else {
							eidx, err = strconv.Atoi(psmlData[len(psmlData)-1][0])
							if err != nil {
								log.Fatal(err)
							}
							eidx += 1 // beyond end of last frame
							c.KillAfterReadingThisMany = len(psmlData) - row
						}
					}
				})
			}

			if ps.DisplayFilter() != "" {
				displayFilterStr = fmt.Sprintf("(%s) and (frame.number >= %d) and (frame.number < %d)", ps.DisplayFilter(), sidx, eidx)
			} else {
				displayFilterStr = fmt.Sprintf("(frame.number >= %d) and (frame.number < %d)", sidx, eidx)
			}

			// These need to be set after displayFilterStr is set but before stage 2 is started
			pdmlCmd = ps.Commands().Pdml(c.PcapPdml, displayFilterStr)
			pcapCmd = ps.Commands().Pcap(c.PcapPcap, displayFilterStr)

		}, &c.stage2Wg, Goroutinewg)

		//======================================================================

		pdmlPidChan := make(chan int)
		pcapPidChan := make(chan int)

		pdmlTermChan := make(chan error)
		pcapTermChan := make(chan error)

		pdmlCtx, pdmlCancelFn := context.WithCancel(c.stage2Ctx)
		pcapCtx, pcapCancelFn := context.WithCancel(c.stage2Ctx)

		//
		// Goroutine to track pdml and pcap process lifetimes
		//
		termshark.TrackedGo(func() {
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				return
			}

			var err error
			stage2CtxChan := c.stage2Ctx.Done()
			pdmlPidChan := pdmlPidChan
			pcapPidChan := pcapPidChan

			pdmlCancelledChan := pdmlCtx.Done()
			pcapCancelledChan := pcapCtx.Done()

			pdmlState := NotStarted
			pcapState := NotStarted

			killPcap := func() {
				err := termshark.KillIfPossible(pcapCmd)
				if err != nil {
					log.Infof("Did not kill pcap process: %v", err)
				}
			}

			killPdml := func() {
				err = termshark.KillIfPossible(pdmlCmd)
				if err != nil {
					log.Infof("Did not kill pdml process: %v", err)
				}
			}

		loop:
			for {
				select {

				case err = <-pdmlTermChan:
					pdmlState = Terminated

				case err = <-pcapTermChan:
					pcapState = Terminated

				case pid := <-pdmlPidChan:
					// this channel can be closed on a stage2 cancel, before the
					// pdml process has been started, meaning we get nil for the
					// pid. If that's the case, don't save the cmd, so we know not
					// to try to kill anything later.
					pdmlPidChan = nil // don't select on this channel again
					if pid != 0 {
						pdmlState = Started
						// gcla later todo - use lock?
						c.PdmlPid = pid
						if stage2CtxChan == nil || pdmlCancelledChan == nil {
							// means that stage2 has been cancelled (so stop the load), and
							// pdmlCmd != nil => for sure a process was started. So kill it.
							// It won't have been cleaned up anywhere else because Wait() is
							// only called below, in this goroutine.
							killPdml()
						}
					}

				case pid := <-pcapPidChan:
					pcapPidChan = nil // don't select on this channel again
					if pid != 0 {
						pcapState = Started
						c.PcapPid = pid
						if stage2CtxChan == nil || pcapCancelledChan == nil {
							killPcap()
						}
					}

				case <-pdmlCancelledChan:
					pdmlCancelledChan = nil // don't select on this channel again
					setPdmlCancelled()
					if pdmlState == Started {
						killPdml()
					}

				case <-pcapCancelledChan:
					pcapCancelledChan = nil // don't select on this channel again
					setPcapCancelled()
					if pcapState == Started {
						// means that for sure, a process was started
						killPcap()
					}

				case <-stage2CtxChan:
					// This will automatically signal pdmlCtx.Done and pcapCtx.Done()

					// Once the pcap/pdml load is initiated, we guarantee we get a stage2 cancel
					// once all the stage2 goroutines are finished. So we don't quit the select loop
					// until this channel (as well as the others) has received a signal
					stage2CtxChan = nil
				}

				// if pdmlpidchan is nil, it means the the channel has been closed or we've received a message
				// a message means the proc has started
				// closed means it won't be started
				// if closed, then pdmlCmd == nil
				// 04/11/21: I can't take a shortcut here and condition on Terminated || (cancelledChan == nil && NotStarted)
				// See the pcap or pdml goroutines below. I block at the beginning, checking on the stage2 cancellation.
				// If I get past that point, and there are no errors in the process invocation, I am guaranteed to start both
				// the pdml and pcap processes. If there are errors, I am guaranteed to close the pcapPidChan with a defer.
				// If I take a shortcut and end this goroutine via a stage2 cancellation before waiting for the pcap pid,
				// then I'll block in that goroutine, trying to send to the pcapPidChan, but with nothing here to receive
				// the value. In the pcap process goroutine, if I get past the stage2 cancellation check, then I need to
				// have something to receive the pid - this goroutine. It needs to stay alive until it gets the pid, or a
				// zero.
				if (pdmlState == Terminated || (pdmlPidChan == nil && c.PdmlPid == 0)) &&
					(pcapState == Terminated || (pcapPidChan == nil && c.PcapPid == 0)) {
					// nothing to select on so break
					break loop
				}
			}
		}, Goroutinewg)

		//======================================================================

		//
		// Goroutine to run pdml process
		//
		termshark.TrackedGo(func() {
			// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
			// quit if that happens first
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				close(pdmlPidChan)
				return
			}

			// We didn't get a stage2 cancel yet. We could now, but for now we've been told to continue
			// now we'll guarantee either:
			// - we'll send the pdml pid on pdmlPidChan if it starts
			// - we'll close the channel if it doesn't start

			pid := 0

			defer func() {
				// Guarantee that at the end of this goroutine, if we didn't start a process (pid == 0)
				// we will close the channel to signal the Wait() goroutine above.
				if pid == 0 {
					close(pdmlPidChan)
				}
			}()

			pdmlOut, err := pdmlCmd.StdoutReader()
			if err != nil {
				HandleError(PdmlCode, app, err, cb)
				return
			}

			err = pdmlCmd.Start()
			if err != nil {
				err = fmt.Errorf("Error starting PDML process %v: %v", pdmlCmd, err)
				HandleError(PdmlCode, app, err, cb)
				return
			}

			log.Infof("Started PDML command %v with pid %d", pdmlCmd, pdmlCmd.Pid())

			pid = pdmlCmd.Pid()
			pdmlPidChan <- pid

			d := xml.NewDecoder(pdmlOut)
			packets := make([]IPdmlPacket, 0, c.opt.PacketsPerLoad)
			issuedKill := false
			readAllRequiredPdml := false
			var packet PdmlPacket
			var cpacket IPdmlPacket
		Loop:
			for {
				tok, err := d.Token()
				if err != nil {
					if !issuedKill && unexpectedPdmlError(err) {
						err = fmt.Errorf("Could not read PDML data: %v", err)
						issuedKill = true
						pdmlCancelFn()
						HandleError(PdmlCode, app, err, cb)
					}
					if err == io.EOF {
						readAllRequiredPdml = true
					}
					break
				}
				switch tok := tok.(type) {
				case xml.StartElement:
					switch tok.Name.Local {
					case "packet":
						err := d.DecodeElement(&packet, &tok)
						if err != nil {
							if !issuedKill && unexpectedPdmlError(err) {
								err = fmt.Errorf("Could not decode PDML data: %v", err)
								issuedKill = true
								pdmlCancelFn()
								HandleError(PdmlCode, app, err, cb)
							}
							break Loop
						}
						// Enabled for now - do something more subtle perhaps in the future
						if true {
							cpacket = SnappyPdmlPacket(packet)
						} else {
							cpacket = packet
						}
						packets = append(packets, cpacket)
						ps.updateCacheEntryWithPdml(row, packets, false)
						if len(packets) == c.KillAfterReadingThisMany {
							// Shortcut - we never take more than abcdex - so just kill here
							issuedKill = true
							readAllRequiredPdml = true
							c.pdmlStoppedDeliberately_ = true
							pdmlCancelFn()
						}
					}

				}

			}

			// The Wait has to come after the last read, which is above
			pdmlTermChan <- pdmlCmd.Wait()

			// Want to preserve invariant - for simplicity - that we only add full loads
			// to the cache

			ps.MainRun(gowid.RunFunction(func(gowid.IApp) {
				// never evict row 0
				ps.PacketCacheFn().Get(0)
				if c.highestCachedRow != -1 {
					// try not to evict "end"
					ps.PacketCacheFn().Get(c.highestCachedRow)
				}

				// the cache entry is marked complete if we are not reading from a fifo, which implies
				// the source of packets will not grow larger. If it could grow larger, we want to ensure
				// that termshark doesn't think that there are only 900 packets, because that's what's
				// in the cache from a previous request - now there might be 950 packets.
				//
				// If the PDML routine was stopped programmatically, that implies the load was not complete
				// so we don't mark the cache as complete then either.
				markComplete := false
				if !ps.ReadingFromFifo() && readAllRequiredPdml {
					markComplete = true
				}
				ps.updateCacheEntryWithPdml(row, packets, markComplete)
				if row > c.highestCachedRow {
					c.highestCachedRow = row
				}
			}))
		}, &c.stage2Wg, Goroutinewg)

		//======================================================================

		//
		// Goroutine to run pcap process
		//
		termshark.TrackedGo(func() {
			// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
			// quit if that happens first
			select {
			case <-c.startChan:
			case <-c.stage2Ctx.Done():
				close(pcapPidChan)
				return
			}

			pid := 0

			defer func() {
				if pid == 0 {
					close(pcapPidChan)
				}
			}()

			pcapOut, err := pcapCmd.StdoutReader()
			if err != nil {
				HandleError(PdmlCode, app, err, cb)
				return
			}

			err = pcapCmd.Start()
			if err != nil {
				// e.g. on the pi
				err = fmt.Errorf("Error starting PCAP process %v: %v", pcapCmd, err)
				HandleError(PdmlCode, app, err, cb)
				return
			}

			log.Infof("Started pcap command %v with pid %d", pcapCmd, pcapCmd.Pid())

			pid = pcapCmd.Pid()
			pcapPidChan <- pid

			packets := make([][]byte, 0, c.opt.PacketsPerLoad)
			issuedKill := false
			readAllRequiredPcap := false
			re := regexp.MustCompile(`([0-9a-f][0-9a-f] )`)
			rd := bufio.NewReader(pcapOut)
			packet := make([]byte, 0)

			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					if !issuedKill && unexpectedPcapError(err) {
						err = fmt.Errorf("Could not read PCAP packet: %v", err)
						HandleError(PdmlCode, app, err, cb)
					}
					if err == io.EOF {
						readAllRequiredPcap = true
					}
					break
				}

				parseResults := re.FindAllStringSubmatch(string(line), -1)

				if len(parseResults) < 1 {
					packets = append(packets, packet)
					packet = make([]byte, 0)

					readEnough := (len(packets) >= c.KillAfterReadingThisMany)
					ps.updateCacheEntryWithPcap(row, packets, false)

					if readEnough && !issuedKill {
						// Shortcut - we never take more than abcdex - so just kill here
						issuedKill = true
						readAllRequiredPcap = true
						pcapCancelFn()
					}
				} else {
					// Ignore line number
					for _, parsedByte := range parseResults[1:] {
						b, err := strconv.ParseUint(string(parsedByte[0][0:2]), 16, 8)
						if err != nil {
							err = fmt.Errorf("Could not read PCAP packet: %v", err)
							if !issuedKill {
								HandleError(PdmlCode, app, err, cb)
							}
							break
						}
						packet = append(packet, byte(b))
					}
				}
			}

			// The Wait has to come after the last read, which is above
			pcapTermChan <- pcapCmd.Wait()

			// I just want to ensure I read it from ram, obviously this is racey
			// never evict row 0
			ps.PacketCacheFn().Get(0)
			if c.highestCachedRow != -1 {
				// try not to evict "end"
				ps.PacketCacheFn().Get(c.highestCachedRow)
			}
			markComplete := false
			if !ps.ReadingFromFifo() && readAllRequiredPcap {
				markComplete = true
			}
			ps.updateCacheEntryWithPcap(row, packets, markComplete)

		}, &c.stage2Wg, Goroutinewg)

	}, Goroutinewg)

}

// waitForFileData sets an inotify watch on filename, and returns when a WRITE
// event is seen.  There is special logic for the case where the file is
// removed; then the watcher is deleted and reinstated. This is to handle a
// specific loading bug in termshark due to an optimized packet capture
// process. To capture packets, termshark runs itself with a special env var
// set.  It detects this at startup, then launches dumpcap as the first
// capture method. If this fails (e.g. the source is an extcap), it launches
// tshark instead. Dumpcap is more efficient, but tshark is needed for the
// extcap sources. The problem is that termshark needs a heuristic for when
// packets have actually been detected - this is so it can wait to launch the
// UI (in case a password is needed at the terminal, I don't want to obscure
// that with the UI). So termshark waits for a WRITE to the pcap generated by
// the capture process, and then launches tail. BUT - if dumpcap fails, it
// will delete (unlink) the capture file passed to it with the -w argument
// before tshark starts. If we don't watch for WRITE, this triggers the
// notifier; then tail starts; then tail fails because depending on timing,
// tshark may not have started yet and so the tail target pcap does not exist.
// The fix is to monitor for inotify REMOVE too, and if seen, recreate the
// pcap file (empty), and restart the watcher. And importantly, don't let
// the tail process start until the WRITE event is seen.
func waitForFileData(ctx context.Context, filename string, errFn func(error)) {
OuterLoop:
	for {
		// this set up is so that I can detect when there are actually packets to read (e.g
		// maybe there's no traffic on the interface). When there's something to read, the
		// rest of the procedure can spring into action. Why not spring into action right away?
		// Because the tail command needs a file to exist to watch it with -f. Can I rely on
		// tail -F across all supported platforms? (e.g. Windows)
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			err = fmt.Errorf("Could not create FS watch: %v", err)
			errFn(err)
			return
		}
		defer watcher.Close()

		file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			err = fmt.Errorf("Could not touch temporary pcap file %s: %v", filename, err)
			errFn(err)
		}
		file.Close()

		if err := watcher.Add(filename); err != nil {
			err = fmt.Errorf("Could not set up watcher for %s: %v", filename, err)
			errFn(err)
			return
		}

		removeWatcher := func(file string) {
			if watcher != nil {
				watcher.Remove(file)
				watcher = nil
			}
		}

		// Make sure that no matter what happens from here on, the watcher is not leaked. But we'll remove
		// it earlier under normal operation so that setting and removing watches with new loaders do not
		// race.
		defer removeWatcher(filename)

	NotifyLoop:
		for {
			select {
			case fe := <-watcher.Events:
				if fe.Name == filename {
					switch fe.Op {
					case fsnotify.Remove:
						removeWatcher(filename)
						continue OuterLoop
					default:
						break NotifyLoop
					}
				}
			case err := <-watcher.Errors:
				err = fmt.Errorf("Unexpected watcher error for %s: %v", filename, err)
				errFn(err)
				return
			case <-ctx.Done():
				return
			}
		}

		break OuterLoop
	}
}

// loadPsmlSync starts tshark processes, and other processes, to generate PSML
// data. There is coordination with the PDML loader via a channel,
// startStage2Chan. If a filter is set, then we might need to read far more
// than a block of 1000 PDML packets (via frame.number <= 4000, for example),
// and we don't know how many to read until the PSML is loaded. We don't want
// to only load one PDML packet at a time, and reload as the user hits arrow
// down through the PSML (in the case the packets selected by the filter are
// very spaced out).
//
// The flow is as follows:
// - if the source of packets is a fifo/interface then
//   - create a pipe
//   - set PcapPsml to a Reader object that tracks bytes read from the pipe
// - start the PSML tshark command and get its stdout
// - if the source of packets is a fifo/interface then
//   - use inotify to wait for the tmp pcap file to appear
//   - start the tail command to read the tmp file created by the interface loader
// - read the PSML and add to data structures
//
// Goroutines are started to track the process lifetimes of both processes.
//
func (p *PsmlLoader) loadPsmlSync(iloader *InterfaceLoader, e iPsmlLoaderEnv, cb interface{}, app gowid.IApp) {
	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	p.psmlCtx, p.psmlCancelFn = context.WithCancel(e.Context())
	p.tailCtx, p.tailCancelFn = context.WithCancel(e.Context())

	intPsmlCtx, intPsmlCancelFn := context.WithCancel(context.Background())

	p.state = Loading

	//======================================================================

	var psmlOut io.ReadCloser

	// Only start this process if we are in interface mode
	var err error
	var fifoPipeReader *os.File
	var fifoPipeWriter *os.File

	//======================================================================

	// Make sure we start the goroutine that monitors for shutdown early - so if/when
	// a shutdown happens, and we get blocked in the XML parser, this will be able to
	// respond
	psmlPidChan := make(chan int)
	tailPidChan := make(chan int)
	psmlTermChan := make(chan error)
	tailTermChan := make(chan error)
	psmlPid := 0 // 0 means not running
	tailPid := 0

	//======================================================================

	termshark.TrackedGo(func() {

		e.MainRun(gowid.RunFunction(func(app gowid.IApp) {
			HandleBegin(PsmlCode, app, cb)
		}))

		defer func(ch chan struct{}) {
			// This will signal goroutines using select on this channel to terminate - like
			// ticker routines that update the packet list UI with new data every second.
			close(p.PsmlFinishedChan)

			e.MainRun(gowid.RunFunction(func(gowid.IApp) {
				HandleEnd(PsmlCode, app, cb)
				p.state = NotLoading
				p.psmlCancelFn = nil
			}))
		}(p.PsmlFinishedChan)

		//======================================================================

		// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
		if e.DisplayFilter() == "" || p.ReadingFromFifo() {
			// don't hold up pdml and pcap generators. If the filter is "", then the frame numbers
			// equal the row numbers, so we don't need the psml to map from row -> frame.
			//
			// And, if we are in interface mode, we won't reach the end of the psml anyway.
			//
			close(p.startStage2Chan)
		}

		//======================================================================

		closedPipe := false
		closePipe := func() {
			if !closedPipe {
				fifoPipeWriter.Close()
				fifoPipeReader.Close()
				closedPipe = true
			}
		}

		if p.ReadingFromFifo() {
			// PcapPsml will be nil if here

			// Build a pipe - the side to be read from will be given to the PSML process
			// and the side to be written to is given to the tail process, which feeds in
			// data from the pcap source.
			//
			fifoPipeReader, fifoPipeWriter, err = os.Pipe()
			if err != nil {
				err = fmt.Errorf("Could not create pipe: %v", err)
				HandleError(PsmlCode, app, err, cb)
				intPsmlCancelFn()
				return
			}
			// pw is used as Stdout for the tail command, which unwinds in this
			// goroutine - so we can close at this point in the unwinding. pr
			// is used as stdin for the psml command, which also runs in this
			// goroutine.
			defer func() {
				closePipe()
			}()

			// wrap the read end of the pipe with a Read() function that counts
			// bytes. If they are equal to the total bytes written to the tmpfile by
			// the tshark -i process, then that means the source is exhausted, and
			// the tail + psml processes are stopped.
			p.PcapPsml = &tailReadTracker{
				tailReader: fifoPipeReader,
				loader:     iloader,
				tail:       e,
				callback:   cb,
				app:        app,
			}
		}

		// Set c.PsmlCmd before it's referenced in the goroutine below. We want to be
		// sure that if if psmlCmd is nil then that means the process has finished (not
		// has not yet started)
		p.PsmlCmd = e.Commands().Psml(p.PcapPsml, e.DisplayFilter())

		// this channel always needs to be signalled or else the goroutine below won't terminate.
		// Closing it will pass a zero-value int (pid) to the goroutine which will understand that
		// means the psml process is NOT running, so it won't call cmd.Wait() on it.
		defer func() {
			if psmlPid == 0 {
				close(psmlPidChan)
			}
		}()

		//======================================================================
		// Goroutine to track process state changes
		termshark.TrackedGo(func() {
			cancelledChan := p.psmlCtx.Done()
			intCancelledChan := intPsmlCtx.Done()

			var err error
			psmlCmd := p.PsmlCmd
			pidChan := psmlPidChan
			state := NotStarted

			kill := func() {
				err := termshark.KillIfPossible(psmlCmd)
				if err != nil {
					log.Infof("Did not kill tshark psml process: %v", err)
				}

				if p.ReadingFromFifo() {
					closePipe()
				}
			}

		loop:
			for {
				select {
				case err = <-psmlTermChan:
					state = Terminated
					if !p.psmlStoppedDeliberately_ {
						if err != nil {
							if _, ok := err.(*exec.ExitError); ok {
								HandleError(PsmlCode, app, MakeUsefulError(psmlCmd, err), cb)
							}
						}
					}

				case <-cancelledChan:
					intPsmlCancelFn() // start internal shutdown
					cancelledChan = nil

				case <-intCancelledChan:
					intCancelledChan = nil
					if state == Started {
						kill()
					}

				case pid := <-pidChan:
					pidChan = nil
					if pid != 0 {
						state = Started
						if intCancelledChan == nil {
							kill()
						}
					}
				}

				if state == Terminated || (pidChan == nil && state == NotStarted) {
					break loop
				}
			}

		}, Goroutinewg)

		//======================================================================

		psmlOut, err = p.PsmlCmd.StdoutReader()
		if err != nil {
			err = fmt.Errorf("Could not access pipe output: %v", err)
			HandleError(PsmlCode, app, err, cb)
			intPsmlCancelFn()
			return
		}

		err = p.PsmlCmd.Start()
		if err != nil {
			err = fmt.Errorf("Error starting PSML command %v: %v", p.PsmlCmd, err)
			HandleError(PsmlCode, app, err, cb)
			intPsmlCancelFn()
			return
		}

		log.Infof("Started PSML command %v with pid %d", p.PsmlCmd, p.PsmlCmd.Pid())

		// Do this here because code later can return early - e.g. the watcher fails to be
		// set up - and then we'll never issue a Wait
		waitedForPsml := false

		// Prefer a defer rather than a goroutine here. That's because otherwise, this goroutine
		// and the XML processing routine reading the process's StdoutPipe are running in parallel,
		// and the XML routine should not issue a Read() (which it does behind the scenes) after
		// Wait() has been called.
		waitForPsml := func() {
			if !waitedForPsml {
				psmlTermChan <- p.PsmlCmd.Wait()
				waitedForPsml = true
			}
		}

		defer waitForPsml()

		psmlPid = p.PsmlCmd.Pid()
		psmlPidChan <- psmlPid

		//======================================================================

		// If it was cancelled, then we don't need to start the tail process because
		// psml will read from the tmp pcap file generated by the interface reading
		// process.

		p.tailCmd = nil

		// Need to run dumpcap -i eth0 -w <tmppcapfile>
		if p.ReadingFromFifo() {
			p.tailCmd = e.Commands().Tail(e.InterfaceFile())

			defer func() {
				if tailPid == 0 {
					close(tailPidChan)
				}
			}()

			//======================================================================
			// process lifetime goroutine for the tail process:
			// tshark -i > tmp
			// tail -f tmp | tshark -i - -t psml
			// ^^^^^^^^^^^
			termshark.TrackedGo(func() {
				cancelledChan := p.tailCtx.Done()

				var err error
				tailCmd := p.tailCmd
				pidChan := tailPidChan
				state := NotStarted

				kill := func() {
					err := termshark.KillIfPossible(tailCmd)
					if err != nil {
						log.Infof("Did not kill tshark tail process: %v", err)
					}
				}

			loop:
				for {
					select {
					case err = <-tailTermChan:
						state = Terminated
						// Don't close the pipe - the psml might not have finished reading yet
						// gcla later todo - is this right or wrong

						// Close the pipe so that the psml reader gets EOF and will also terminate;
						// otherwise the PSML reader will block waiting for more data from the pipe
						fifoPipeWriter.Close()
						if !p.psmlStoppedDeliberately_ && !e.TailStoppedDeliberately() {
							if err != nil {
								if _, ok := err.(*exec.ExitError); ok {
									HandleError(PsmlCode, app, MakeUsefulError(tailCmd, err), cb)
								}
							}
						}

					case <-cancelledChan:
						cancelledChan = nil
						if state == Started {
							kill()
						}

					case pid := <-pidChan:
						pidChan = nil
						if pid != 0 {
							state = Started
							if cancelledChan == nil {
								kill()
							}
						}
					}

					// successfully started then died/kill, OR
					// was never started, won't be started, and cancelled
					if state == Terminated || (pidChan == nil && state == NotStarted) {
						break loop
					}
				}
			}, Goroutinewg)

			//======================================================================

			p.tailCmd.SetStdout(fifoPipeWriter)

			waitForFileData(intPsmlCtx,
				e.InterfaceFile(),
				func(err error) {
					HandleError(PsmlCode, app, err, cb)
					intPsmlCancelFn()
					p.tailCancelFn() // needed to end the goroutine, end if tailcmd has not started
				},
			)

			log.Infof("Starting Tail command: %v", p.tailCmd)

			err = p.tailCmd.Start()
			if err != nil {
				err = fmt.Errorf("Could not start tail command %v: %v", p.tailCmd, err)
				HandleError(PsmlCode, app, err, cb)
				intPsmlCancelFn()
				p.tailCancelFn() // needed to end the goroutine, end if tailcmd has not started
				return
			}

			termshark.TrackedGo(func() {
				tailTermChan <- p.tailCmd.Wait()
			}, Goroutinewg)

			tailPid = p.tailCmd.Pid()
			tailPidChan <- tailPid
		} // end of reading from fifo

		//======================================================================

		//
		// Goroutine to read psml xml and update data structures
		//
		defer func(ch chan struct{}) {
			select {
			case <-ch:
				// already done/closed, do nothing
			default:
				close(ch)
			}

			// This will kill the tail process if there is one
			intPsmlCancelFn() // stop the ticker
		}(p.startStage2Chan)

		d := xml.NewDecoder(psmlOut)

		// <packet>
		// <section>1</section>
		// <section>0.000000</section>
		// <section>192.168.44.123</section>
		// <section>192.168.44.213</section>
		// <section>TFTP</section>
		// <section>77</section>
		// <section>Read Request, File: C:\IBMTCPIP\lccm.1, Transfer type: octet</section>
		// </packet>

		var curPsml []string
		var curCounts []int
		var fg string
		var bg string
		var pidx int
		ppidx := 0 // the previous packet number read; 0 means no packet. I can use 0 because
		// the psml I read will start at packet 1 so - map[0] => 1st packet
		ready := false
		empty := true
		structure := false
		for {
			if intPsmlCtx.Err() != nil {
				break
			}
			tok, err := d.Token()
			if err != nil {
				// gcla later todo - LoadWasCancelled is checked outside of the main goroutine here
				if err != io.EOF && !e.LoadWasCancelled() {
					err = fmt.Errorf("Could not read PSML data: %v", err)
					HandleError(PsmlCode, app, err, cb)
				}
				break
			}
			switch tok := tok.(type) {
			case xml.EndElement:
				switch tok.Name.Local {
				case "structure":
					structure = false
					p.Lock()
					// Don't keep the first column - we add on column number to all PSML
					// loads whether or not the user wants it to track table number -> packet
					// number. This is then stripped from the columns shown to the user.
					p.packetPsmlHeaders = p.packetPsmlHeaders[1:]
					p.Unlock()
				case "packet":
					p.Lock()

					// Track the mapping of packet number <section>12</section> to position
					// in the table e.g. 5th element. This is so that I can jump to the correct
					// row with marks even if a filter is currently applied.
					pidx, err = strconv.Atoi(curPsml[0])
					if err != nil {
						log.Fatal(err)
					}
					p.PacketNumberMap[pidx] = len(p.packetPsmlData)
					p.PacketNumberOrder[ppidx] = pidx
					ppidx = pidx

					p.packetPsmlData = append(p.packetPsmlData, curPsml[1:])

					if len(p.packetAverageLength) > len(curPsml)-1 {
						p.packetAverageLength = p.packetAverageLength[0 : len(curPsml)-1]
					}
					if len(p.packetMaxLength) > len(curPsml)-1 {
						p.packetMaxLength = p.packetMaxLength[0 : len(curPsml)-1]
					}

					for i, ct := range curCounts[1:] {
						// skip the first one - that's not displayed in the UI. We always have element 0 as No.
						p.packetAverageLength[i].update(ct)
						p.packetMaxLength[i].update(ct)
					}

					p.packetPsmlColors = append(p.packetPsmlColors, PacketColors{
						FG: psmlColorToIColor(fg),
						BG: psmlColorToIColor(bg),
					})
					p.Unlock()

				case "section":
					ready = false
					// Means we got </section> without any char data i.e. empty <section>
					if empty {
						curCounts = append(curCounts, 0)
						curPsml = append(curPsml, "")
					}
				}
			case xml.StartElement:
				switch tok.Name.Local {
				case "structure":
					structure = true
				case "packet":
					curPsml = make([]string, 0, 10)
					curCounts = make([]int, 0, 10)
					fg = ""
					bg = ""
					for _, attr := range tok.Attr {
						switch attr.Name.Local {
						case "foreground":
							fg = attr.Value
						case "background":
							bg = attr.Value
						}
					}
				case "section":
					ready = true
					empty = true
				}
			case xml.CharData:
				if ready {
					if structure {
						p.Lock()
						p.packetPsmlHeaders = append(p.packetPsmlHeaders, string(tok))
						p.Unlock()
						e.MainRun(gowid.RunFunction(func(app gowid.IApp) {
							handlePsmlHeader(PsmlCode, app, cb)
						}))
					} else {
						curPsml = append(curPsml, string(format.TranslateHexCodes(tok)))
						curCounts = append(curCounts, len(curPsml[len(curPsml)-1]))
						empty = false
					}
				}
			}
		}

	}, Goroutinewg)

}

func (c *PsmlLoader) DoWithPsmlData(fn func([][]string)) {
	c.Lock()
	defer c.Unlock()
	fn(c.packetPsmlData)
}

func (c *PsmlLoader) ReadingFromFifo() bool {
	// If it's a string it means that it's a filename, so it's not a fifo. Other values
	// in practise are the empty interface, or the read end of a fifo
	_, ok := c.PcapPsml.(string)
	return !ok
}

func (c *PsmlLoader) IsLoading() bool {
	return c.state == Loading
}

func (c *PsmlLoader) StartStage2ChanFn() chan struct{} {
	return c.startStage2Chan
}

func (c *PsmlLoader) PacketCacheFn() *lru.Cache { // i -> [pdml(i * 1000)..pdml(i+1*1000)]
	return c.PacketCache
}

// Assumes this is a clean stop, not an error
func (p *ParentLoader) stopTail() {
	p.tailStoppedDeliberately = true
	if p.tailCancelFn != nil {
		p.tailCancelFn()
	}
}

func (p *PsmlLoader) PacketsPerLoad() int {
	p.Lock()
	defer p.Unlock()
	return p.opt.PacketsPerLoad
}

func (p *PsmlLoader) stopLoadPsml() {
	p.psmlStoppedDeliberately_ = true
	if p.psmlCancelFn != nil {
		p.psmlCancelFn()
	}
}

func (p *PsmlLoader) PsmlData() [][]string {
	return p.packetPsmlData
}

func (p *PsmlLoader) PsmlHeaders() []string {
	return p.packetPsmlHeaders
}

func (p *PsmlLoader) PsmlColors() []PacketColors {
	return p.packetPsmlColors
}

func (p *PsmlLoader) PsmlAverageLengths() []gwutil.IntOption {
	res := make([]gwutil.IntOption, 0, len(p.packetAverageLength))
	for _, avg := range p.packetAverageLength {
		res = append(res, avg.average())
	}
	return res
}

func (p *PsmlLoader) PsmlMaxLengths() []int {
	res := make([]int, 0, len(p.packetMaxLength))
	for _, maxer := range p.packetMaxLength {
		res = append(res, int(maxer.max()))
	}
	return res
}

// if done==true, then this cache entry is complete
func (p *PsmlLoader) updateCacheEntryWithPdml(row int, pdml []IPdmlPacket, done bool) {
	var ce CacheEntry
	p.Lock()
	defer p.Unlock()
	if ce2, ok := p.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pdml = pdml
	ce.PdmlComplete = done
	p.PacketCache.Add(row, ce)
}

func (p *PsmlLoader) updateCacheEntryWithPcap(row int, pcap [][]byte, done bool) {
	var ce CacheEntry
	p.Lock()
	defer p.Unlock()
	if ce2, ok := p.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pcap = pcap
	ce.PcapComplete = done
	p.PacketCache.Add(row, ce)
}

func (p *PsmlLoader) LengthOfPdmlCacheEntry(row int) (int, error) {
	p.Lock()
	defer p.Unlock()
	if ce, ok := p.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pdml), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

func (p *PsmlLoader) LengthOfPcapCacheEntry(row int) (int, error) {
	p.Lock()
	defer p.Unlock()
	if ce, ok := p.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pcap), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

func (c *PsmlLoader) CacheAt(row int) (CacheEntry, bool) {
	if ce, ok := c.PacketCache.Get(row); ok {
		return ce.(CacheEntry), ok
	}
	return CacheEntry{}, false
}

func (c *PsmlLoader) NumLoaded() int {
	c.Lock()
	defer c.Unlock()
	return len(c.packetPsmlData)
}

//======================================================================

func (c *PdmlLoader) IsLoading() bool {
	return c.state == Loading
}

func (c *PdmlLoader) LoadIsVisible() bool {
	return c.visible
}

// Only call from main goroutine
func (c *PdmlLoader) LoadingRow() int {
	return c.rowCurrentlyLoading
}

func (p *PdmlLoader) stopLoadPdml() {
	p.pdmlStoppedDeliberately_ = true
	if p.stage2CancelFn != nil {
		p.stage2CancelFn()
	}
}

//======================================================================

type iTailCommand interface {
	stopTail()
}

type iIfaceLoaderEnv interface {
	iLoaderEnv
	iTailCommand
	PsmlStoppedDeliberately() bool
	InterfaceFile() string
	PacketSources() []IPacketSource
	CaptureFilter() string
}

// dumpcap -i eth0 -w /tmp/foo.pcap
// dumpcap -i /dev/fd/3 -w /tmp/foo.pcap
func (i *InterfaceLoader) loadIfacesSync(e iIfaceLoaderEnv, cb interface{}, app gowid.IApp) {
	i.totalFifoBytesWritten = gwutil.NoneInt64()

	i.ifaceCtx, i.ifaceCancelFn = context.WithCancel(e.Context())

	log.Infof("Starting Iface command: %v", i.ifaceCmd)

	pid := 0
	ifacePidChan := make(chan int)

	defer func() {
		if pid == 0 {
			close(ifacePidChan)
		}
	}()

	// tshark -i eth0 -w foo.pcap
	i.ifaceCmd = e.Commands().Iface(SourcesNames(e.PacketSources()), e.CaptureFilter(), e.InterfaceFile())

	err := i.ifaceCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting interface reader %v: %v", i.ifaceCmd, err)
		HandleError(IfaceCode, app, err, cb)
		return
	}

	ifaceTermChan := make(chan error)

	i.state = Loading

	log.Infof("Started Iface command %v with pid %d", i.ifaceCmd, i.ifaceCmd.Pid())

	// Do this in a goroutine because the function is expected to return quickly
	termshark.TrackedGo(func() {
		ifaceTermChan <- i.ifaceCmd.Wait()
	}, Goroutinewg)

	//======================================================================
	// Process goroutine

	termshark.TrackedGo(func() {
		defer func() {
			// if psrc is a PipeSource, then we open /dev/fd/3 in termshark, and reroute descriptor
			// stdin to number 3 when termshark starts. So to kill the process writing in, we need
			// to close our side of the pipe.
			for _, psrc := range e.PacketSources() {
				if cl, ok := psrc.(io.Closer); ok {
					cl.Close()
				}
			}

			e.MainRun(gowid.RunFunction(func(gowid.IApp) {
				i.state = NotLoading
				i.ifaceCancelFn = nil
			}))

		}()

		cancelledChan := i.ifaceCtx.Done()
		state := NotStarted

		var err error
		pidChan := ifacePidChan

		ifaceCmd := i.ifaceCmd

		killIface := func() {
			err = termshark.KillIfPossible(i.ifaceCmd)
			if err != nil {
				log.Infof("Did not kill iface process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-ifaceTermChan:
				state = Terminated
				if !e.PsmlStoppedDeliberately() && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						// This could be if termshark is started like this: cat nosuchfile.pcap | termshark -i -
						// Then dumpcap will be started with /dev/fd/3 as its stdin, but will fail with EOF and
						// exit status 1.
						HandleError(IfaceCode, app, MakeUsefulError(ifaceCmd, err), cb)
					}
				}

			case pid := <-pidChan:
				// this channel can be closed on a stage2 cancel, before the
				// pdml process has been started, meaning we get nil for the
				// pid. If that's the case, don't save the cmd, so we know not
				// to try to kill anything later.
				pidChan = nil
				if pid != 0 {
					state = Started
					if cancelledChan == nil {
						killIface()
					}
				}

			case <-cancelledChan:
				cancelledChan = nil
				if state == Started {
					killIface()
				}
			}

			// if pdmlpidchan is nil, it means the the channel has been closed or we've received a message
			// a message means the proc has started
			// closed means it won't be started
			// if closed, then pdmlCmd == nil
			if state == Terminated || (pidChan == nil && state == NotStarted) {
				// nothing to select on so break
				break loop
			}
		}

		// Calculate the final size of the tmp file we wrote with packets read from the
		// interface/pipe. This runs after the dumpcap command finishes.
		fi, err := os.Stat(e.InterfaceFile())
		i.Lock()
		if err != nil {
			log.Warn(err)
			// Deliberately not a fatal error - it can happen if the source of packets to tshark -i
			// is corrupt, resulting in a tshark error. Setting zero here will line up with the
			// reading end which will read zero, and so terminate the tshark -T psml procedure.

			if i.fifoError == nil && !os.IsNotExist(err) {
				// Ignore ENOENT because it means there was an error before dumpcap even wrote
				// anything to disk
				i.fifoError = err
			}
		} else {
			i.totalFifoBytesWritten = gwutil.SomeInt64(fi.Size())
		}
		i.Unlock()

		i.checkAllBytesRead(e, cb, app)
	}, Goroutinewg)

	//======================================================================

	pid = i.ifaceCmd.Pid()
	ifacePidChan <- pid
}

// checkAllBytesRead is called (a) when the tshark -i process is finished
// writing to the tmp file and (b) every time the tmpfile tail process reads
// bytes. totalFifoBytesWrite is set to non-nil only when the tail process
// completes. totalFifoBytesRead is updated every read. If they are every
// found to be equal, it means that (1) the tail process has finished, meaning
// killed or has reached EOF with its packet source (e.g. stdin, fifo) and (2)
// the tail process has read all those bytes - so no packets will be
// missed. In that case, the tail process is killed and its stdout closed,
// which will trigger the psml reading process to shut down, and termshark
// will turn off its loading UI.
func (i *InterfaceLoader) checkAllBytesRead(e iTailCommand, cb interface{}, app gowid.IApp) {
	cancel := false
	if !i.totalFifoBytesWritten.IsNone() && !i.totalFifoBytesRead.IsNone() {
		if i.totalFifoBytesRead.Val() == i.totalFifoBytesWritten.Val() {
			cancel = true
		}
	}
	if i.fifoError != nil {
		cancel = true
	}

	// if there was a fifo error, OR we have read all the bytes that were written, then
	// we need to stop the tail command
	if cancel {
		if i.fifoError != nil {
			err := fmt.Errorf("Fifo error: %v", i.fifoError)
			HandleError(IfaceCode, app, err, cb)
		}

		e.stopTail()
	}
}

func (i *InterfaceLoader) stopLoadIface() {
	if i != nil && i.ifaceCancelFn != nil {
		i.ifaceCancelFn()
	}
}

func (c *InterfaceLoader) IsLoading() bool {
	return c != nil && c.state == Loading
}

//======================================================================

type CacheEntry struct {
	Pdml         []IPdmlPacket
	Pcap         [][]byte
	PdmlComplete bool
	PcapComplete bool
}

func (c CacheEntry) Complete() bool {
	return c.PdmlComplete && c.PcapComplete
}

//======================================================================

type LoadPcapSlice struct {
	Row           int
	CancelCurrent bool
	Jump          int // 0 means no jump
}

func (m LoadPcapSlice) String() string {
	pieces := make([]string, 0, 3)
	pieces = append(pieces, fmt.Sprintf("loadslice: %d", m.Row))
	if m.CancelCurrent {
		pieces = append(pieces, fmt.Sprintf("cancelcurrent: %v", m.CancelCurrent))
	}
	if m.Jump != 0 {
		pieces = append(pieces, fmt.Sprintf("jumpto: %d", m.Jump))
	}
	return fmt.Sprintf("[%s]", strings.Join(pieces, ", "))
}

//======================================================================

func ProcessPdmlRequests(requests []LoadPcapSlice, mloader *ParentLoader,
	loader *PdmlLoader, cb interface{}, app gowid.IApp) []LoadPcapSlice {
Loop:
	for {
		if len(requests) == 0 {
			break
		} else {
			ev := requests[0]

			if !mloader.loadIsNecessary(ev) {
				requests = requests[1:]
			} else {
				if loader.state == Loading {
					if ev.CancelCurrent {
						loader.stopLoadPdml()
					}
				} else {
					mloader.RenewPdmlLoader()
					// ops?
					mloader.loadPcapSync(ev.Row, ev.CancelCurrent, mloader, cb, app)
					requests = requests[1:]
				}
				break Loop
			}
		}
	}
	return requests
}

//======================================================================

func psmlColorToIColor(col string) gowid.IColor {
	if res, err := gowid.MakeRGBColorSafe(col); err != nil {
		return nil
	} else {
		return res
	}
}

// https://stackoverflow.com/a/28005931/784226
func TempPcapFile(tokens ...string) string {
	tokensClean := make([]string, 0, len(tokens))
	for _, token := range tokens {
		re := regexp.MustCompile(`[^a-zA-Z0-9.-]`)
		tokensClean = append(tokensClean, re.ReplaceAllString(token, "_"))
	}

	tokenClean := strings.Join(tokensClean, "-")

	return filepath.Join(termshark.PcapDir(), fmt.Sprintf("%s--%s.pcap",
		tokenClean,
		termshark.DateStringForFilename(),
	))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
