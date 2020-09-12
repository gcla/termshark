// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
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
	"time"

	"github.com/gcla/deep"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/format"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

//======================================================================

var Goroutinewg *sync.WaitGroup

type RunFn func()
type whenFn func() bool

type runFnInState struct {
	when whenFn
	doit RunFn
}

//======================================================================

type LoaderState int

const (
	LoadingPsml  LoaderState = 1 << iota // pcap+pdml might be finished, but this is what was initiated
	LoadingPdml                          // from a cache request
	LoadingIface                         // copying from iface to temp pcap
)

func (c *Loader) State() LoaderState {
	return c.state
}

// Repeatedly go back to the start if anything is triggered.
// Call only on the main thread (running the select loop)
func (c *Loader) SetState(st LoaderState) {
	c.state = st
Outer:
	for {
	Inner:
		for i, sc := range c.onStateChange {
			if sc.when() {
				c.onStateChange = append(c.onStateChange[:i], c.onStateChange[i+1:]...)
				sc.doit()
				break Inner
			}
		}
		break Outer
	}
}

func (t LoaderState) String() string {
	s := make([]string, 0, 3)
	if t&LoadingPsml != 0 {
		s = append(s, "psml")
	}
	if t&LoadingPdml != 0 {
		s = append(s, "pdml")
	}
	if t&LoadingIface != 0 {
		s = append(s, "iface")
	}
	if len(s) == 0 {
		return fmt.Sprintf("idle")
	} else {
		return strings.Join(s, "+")
	}
}

//======================================================================

type IBasicCommand interface {
	fmt.Stringer
	Start() error
	Wait() error
	Pid() int
	Kill() error
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

type Loader struct {
	cmds ILoaderCmds

	state LoaderState // which pieces are currently loading

	SuppressErrors bool // true if loader is in a transient state due to a user operation e.g. stop, reload, etc

	psrcs         []IPacketSource // The canonical struct for the loader's current packet source.
	ifaceFile     string          // The temp pcap file that is created by reading from the interface
	displayFilter string
	captureFilter string

	PcapPsml interface{} // Pcap file source for the psml reader - fifo if iface+!stopped; tmpfile if iface+stopped; pcap otherwise
	PcapPdml string      // Pcap file source for the pdml reader - tmpfile if iface; pcap otherwise
	PcapPcap string      // Pcap file source for the pcap reader - tmpfile if iface; pcap otherwise

	mainCtx         context.Context // cancelling this cancels the dependent contexts - used to close whole loader.
	mainCancelFn    context.CancelFunc
	thisSrcCtx      context.Context // cancelling this cancels the dependent contexts - used to stop current load.
	thisSrcCancelFn context.CancelFunc
	psmlCtx         context.Context // cancels the psml loading process
	psmlCancelFn    context.CancelFunc
	stage2Ctx       context.Context // cancels the pcap/pdml loading process
	stage2CancelFn  context.CancelFunc
	ifaceCtx        context.Context // cancels the iface reader process
	ifaceCancelFn   context.CancelFunc

	//psmlDecodingProcessChan chan struct{} // signalled by psml load stage when the XML decoding is complete - signals rest of stage 1 to shut down
	stage2GoroutineDoneChan chan struct{} // signalled by a goroutine in stage 2 for pcap/pdml - always signalled at end. When x2, signals rest of stage 2 to shut down

	//stage1Wg sync.WaitGroup
	stage2Wg sync.WaitGroup

	// Signalled when the psml is fully loaded (or already loaded) - to tell
	// the pdml and pcap reader goroutines to start - they can then map table
	// row -> frame number
	StartStage2Chan chan struct{}
	// Signalled to start the pdml reader. Will start concurrent with psml if
	// psml loaded already or if filter == "" (then table row == frame number)
	startPdmlChan chan struct{}
	startPcapChan chan struct{}

	PsmlFinishedChan   chan struct{} // closed when entire psml load process is done
	Stage2FinishedChan chan struct{} // closed when entire pdml+pcap load process is done
	IfaceFinishedChan  chan struct{} // closed when interface reader process has shut down (e.g. stopped)

	ifaceCmd IBasicCommand
	tailCmd  ITailCommand
	PsmlCmd  IPcapCommand
	PcapCmd  IPcapCommand
	PdmlCmd  IPcapCommand

	sync.Mutex
	PacketPsmlData    [][]string
	PacketPsmlColors  []PacketColors
	PacketPsmlHeaders []string
	PacketNumberMap   map[int]int // map from actual packet row <section>12</section> to pos in unsorted table
	// This would be affected by a display filter e.g. packet 12 might be the 1st packet in the table.
	// I need this so that if the user jumps to a mark stored as "packet 12", I can find the right table row.
	PacketCache *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)]

	onStateChange []runFnInState

	LoadWasCancelled         bool // True if the last load (iface or file) was halted by the stop button
	RowCurrentlyLoading      int  // set by the pdml loading stage
	highestCachedRow         int
	KillAfterReadingThisMany int // A shortcut - tell pcap/pdml to read one

	// set by the iface procedure when it has finished e.g. the pipe to the fifo has finished, the
	// iface process has been killed, etc. This tells the psml-reading procedure when it should stop i.e.
	// when this many bytes have passed through.
	totalFifoBytesWritten gwutil.Int64Option
	totalFifoBytesRead    gwutil.Int64Option
	fifoError             error

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

func NewPcapLoader(cmds ILoaderCmds, opts ...Options) *Loader {
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

	res := &Loader{
		cmds:                    cmds,
		IfaceFinishedChan:       make(chan struct{}),
		stage2GoroutineDoneChan: make(chan struct{}),
		PsmlFinishedChan:        make(chan struct{}),
		Stage2FinishedChan:      make(chan struct{}),
		onStateChange:           make([]runFnInState, 0),
		RowCurrentlyLoading:     -1,
		highestCachedRow:        -1,
		opt:                     opt,
	}

	res.resetData()
	res.mainCtx, res.mainCancelFn = context.WithCancel(context.Background())

	return res
}

func (c *Loader) resetData() {
	c.Lock()
	defer c.Unlock()
	c.PacketPsmlData = make([][]string, 0)
	c.PacketPsmlColors = make([]PacketColors, 0)
	c.PacketPsmlHeaders = make([]string, 0, 10)
	c.PcapPdml = ""
	packetCache, err := lru.New(c.opt.CacheSize)
	if err != nil {
		log.Fatal(err)
	}
	c.PacketCache = packetCache
}

func (c *Loader) PacketsPerLoad() int {
	c.Lock()
	defer c.Unlock()
	return c.opt.PacketsPerLoad
}

// Close shuts down the whole loader, including progress monitoring goroutines. Use this only
// when about to load a new pcap (use a new loader)
func (c *Loader) Close() error {
	if c.mainCancelFn != nil {
		c.mainCancelFn()
	}
	return nil
}

func (c *Loader) MainContext() context.Context {
	return c.mainCtx
}

func (c *Loader) SourceContext() context.Context {
	return c.thisSrcCtx
}

func (c *Loader) stopLoadIface() {
	if c.ifaceCancelFn != nil {
		c.ifaceCancelFn()
	}
}

func (c *Loader) stopLoadPsml() {
	if c.psmlCancelFn != nil {
		c.psmlCancelFn()
	}
}

func (c *Loader) stopLoadPdml() {
	if c.stage2CancelFn != nil {
		c.stage2CancelFn()
	}
}

func (c *Loader) stopLoadCurrentSource() {
	if c.thisSrcCancelFn != nil {
		c.thisSrcCancelFn()
	}
}

func (c *Loader) PsmlData() [][]string {
	return c.PacketPsmlData
}

func (c *Loader) PsmlHeaders() []string {
	return c.PacketPsmlHeaders
}

func (c *Loader) PsmlColors() []PacketColors {
	return c.PacketPsmlColors
}

//======================================================================

type Scheduler struct {
	*Loader
	OperationsChan chan RunFn
	disabled       bool
}

func NewScheduler(cmds ILoaderCmds, opts ...Options) *Scheduler {
	return &Scheduler{
		OperationsChan: make(chan RunFn, 1000),
		Loader:         NewPcapLoader(cmds, opts...),
	}
}

func (c *Scheduler) IsEnabled() bool {
	return !c.disabled
}

func (c *Scheduler) Enable() {
	c.disabled = false
	c.SuppressErrors = false
}

func (c *Scheduler) Disable() {
	c.disabled = true
	c.SuppressErrors = true
}

func (c *Scheduler) RequestClearPcap(cb interface{}) {
	log.Infof("Scheduler requested clear pcap")
	c.OperationsChan <- func() {
		c.Disable()
		c.doClearPcapOperation(cb, func() {
			c.Enable()
		})

	}
}

func (c *Scheduler) RequestStopLoadStage1(cb interface{}) {
	log.Infof("Scheduler requested stop psml + iface")
	c.OperationsChan <- func() {
		c.Disable()
		c.doStopLoadStage1Operation(cb, func() {
			c.Enable()
		})
	}
}

func (c *Scheduler) RequestStopLoad(cb interface{}) {
	log.Infof("Scheduler requested stop pcap load")
	c.OperationsChan <- func() {
		c.Disable()
		c.doStopLoadOperation(cb, func() {
			c.Enable()
		})
	}
}

func (c *Scheduler) RequestNewFilter(newfilt string, cb interface{}) {
	log.Infof("Scheduler requested application of display filter '%v'", newfilt)
	c.OperationsChan <- func() {
		c.Disable()
		c.doNewFilterOperation(newfilt, cb, c.Enable)
	}
}

func (c *Scheduler) RequestLoadInterfaces(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}) {
	log.Infof("Scheduler requested interface/fifo load for '%v'", SourcesString(psrcs))
	c.OperationsChan <- func() {
		c.Disable()
		c.doLoadInterfacesOperation(psrcs, captureFilter, displayFilter, tmpfile, cb, func() {
			c.Enable()
		})
	}
}

func (c *Scheduler) RequestLoadPcap(pcap string, displayFilter string, cb interface{}) {
	log.Infof("Scheduler requested pcap file load for '%v'", pcap)
	c.OperationsChan <- func() {
		c.Disable()
		c.doLoadPcapOperation(pcap, displayFilter, cb, func() {
			c.Enable()
		})
	}
}

//======================================================================

// Clears the currently loaded data. If the loader is currently reading from an
// interface, the loading continues after the current data has been discarded. If
// the loader is currently reading from a file, the loading *stops*.
func (c *Loader) doClearPcapOperation(cb interface{}, fn RunFn) {
	if c.State() == 0 {
		c.clearSource()
		c.resetData()

		handleClear(cb)

		fn()
	} else {
		// If we are reading from an interface when the clear operation is issued, we should
		// continue again afterwards. If we're reading from a file, the clear stops the read.
		// Track this state.
		startIfaceAgain := false

		if c.State()&LoadingIface != 0 {
			startIfaceAgain = true
			for _, psrc := range c.psrcs {
				startIfaceAgain = startIfaceAgain && CanRestart(psrc) // Only try to restart if the packet source allows
			}
		}

		c.stopLoadCurrentSource()

		c.When(c.IdleState, func() {
			// Document why this needs to be delayed again, since runWhenReadyFn
			// will run in app goroutine
			c.doClearPcapOperation(cb, func() {
				if startIfaceAgain {
					c.doLoadInterfacesOperation(
						c.psrcs, c.CaptureFilter(),
						c.DisplayFilter(), c.InterfaceFile(), cb, fn,
					)
				} else {
					fn()
				}
			})
		})

	}
}

func (c *Loader) IdleState() bool {
	return c.State() == 0
}

func (c *Loader) When(pred whenFn, doit RunFn) {
	c.onStateChange = append(c.onStateChange, runFnInState{pred, doit})
}

func (c *Loader) doStopLoadOperation(cb interface{}, fn RunFn) {
	c.LoadWasCancelled = true

	HandleBegin(cb)

	if c.State() != 0 {
		c.stopLoadCurrentSource()

		c.When(c.IdleState, func() {
			c.doStopLoadOperation(cb, fn)
		})
	} else {
		fn()
		HandleEnd(cb)
	}
}

func (c *Loader) doStopLoadStage1Operation(cb interface{}, fn RunFn) {
	c.LoadWasCancelled = true

	HandleBegin(cb)

	if c.State()&(LoadingPsml|LoadingIface) != 0 {

		if c.State()&LoadingPsml != 0 {
			c.stopLoadPsml()
		}
		if c.State()&LoadingIface != 0 {
			c.stopLoadIface()
		}

		c.When(func() bool {
			return c.State()&(LoadingIface|LoadingPsml) == 0
		}, func() {
			c.doStopLoadStage1Operation(cb, fn)
		})
	} else {
		fn()
		HandleEnd(cb)
	}
}

// Issued e.g. if a new filter is applied while loading from an interface. We need
// to stop the psml (and fifo) and pdml reading processes, but keep alive the spooling
// process from iface -> temp file. When the current state is simply Loadingiface then
// the next operation can commence (e.g. applying the new filter value)
func (c *Loader) doStopLoadToIfaceOperation(fn RunFn) {
	c.stopLoadPsml()
	c.stopLoadPdml()

	c.When(func() bool {
		return c.State() == LoadingIface
	}, fn)
}

// Called when state is appropriate
func (c *Loader) doNewFilterOperation(newfilt string, cb interface{}, fn RunFn) {
	//var res EnableOperationsWhen

	if c.DisplayFilter() == newfilt {
		log.Infof("No operation - same filter applied.")
		fn()
	} else if c.State() == 0 || c.State() == LoadingIface {
		handleClear(cb)

		c.startLoadNewFilter(newfilt, cb)

		c.When(func() bool {
			return c.State()&LoadingPsml == LoadingPsml
		}, fn)

		c.SetState(c.State() | LoadingPsml)

	} else {
		if c.State()&LoadingPsml != 0 {
			c.stopLoadPsml()
		}
		if c.State()&LoadingPdml != 0 {
			c.stopLoadPdml()
		}

		c.When(func() bool {
			return c.State() == 0 || c.State() == LoadingIface
		}, func() {
			c.doNewFilterOperation(newfilt, cb, fn)
		})
	}
}

type IClear interface {
	OnClear(closeMe chan<- struct{})
}

type INewSource interface {
	OnNewSource(closeMe chan<- struct{})
}

type IOnError interface {
	OnError(err error, closeMe chan<- struct{})
}

type IBeforeBegin interface {
	BeforeBegin(closeMe chan<- struct{})
}

type IAfterEnd interface {
	AfterEnd(closeMe chan<- struct{})
}

type IUnpack interface {
	Unpack() []interface{}
}

type HandlerList []interface{}

func (h HandlerList) Unpack() []interface{} {
	return h
}

func (c *Loader) doLoadInterfacesOperation(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}, fn RunFn) {
	// The channel is unbuffered, and monitored from the same goroutine, so this would block
	// unless we start a new goroutine

	//var res EnableOperationsWhen

	// If we're already loading, but the request is for the same, then ignore. If we were stopped, then
	// process the request, because it implicitly means start reading from the interface again (and we
	// are stopped)
	names := SourcesString(psrcs)
	if c.State()&LoadingPsml != 0 && deep.Equal(c.Interfaces(), names) == nil && c.DisplayFilter() == displayFilter && c.CaptureFilter() == captureFilter {
		log.Infof("No operation - same interface and filters.")
		fn()
	} else if c.State() == 0 {
		handleClear(cb)
		handleNewSource(cb)

		if err := c.startLoadInterfacesNew(psrcs, captureFilter, displayFilter, tmpfile, cb); err == nil {
			c.When(func() bool {
				return c.State()&(LoadingIface|LoadingPsml) == LoadingIface|LoadingPsml
			}, fn)

			c.SetState(c.State() | LoadingIface | LoadingPsml)
		} else {
			HandleError(err, cb)
		}
	} else if c.State() == LoadingIface && deep.Equal(c.Interfaces(), names) == nil {
		//if iface == c.Interface() { // same interface, so just start it back up - iface spooler still running
		handleClear(cb)
		c.startLoadNewFilter(displayFilter, cb)

		c.When(func() bool {
			return c.State()&(LoadingIface|LoadingPsml) == LoadingIface|LoadingPsml
		}, fn)

		c.SetState(c.State() | LoadingPsml)
	} else {
		// State contains Loadingpdml and/or Loadingpdml. Need to stop those first. OR state contains
		// Loadingiface but the interface requested is different.
		if c.State()&LoadingIface != 0 && deep.Equal(c.Interfaces(), names) != nil {
			c.doStopLoadOperation(cb, func() {
				c.doLoadInterfacesOperation(psrcs, captureFilter, displayFilter, tmpfile, cb, fn)
			}) // returns an enable function when idle
		} else {
			c.doStopLoadToIfaceOperation(func() {
				c.doLoadInterfacesOperation(psrcs, captureFilter, displayFilter, tmpfile, cb, fn)
			})
		}
	}
}

// Call from app goroutine context
func (c *Loader) doLoadPcapOperation(pcap string, displayFilter string, cb interface{}, fn RunFn) {
	curDisplayFilter := displayFilter
	// The channel is unbuffered, and monitored from the same goroutine, so this would block
	// unless we start a new goroutine

	if c.Pcap() == pcap && c.DisplayFilter() == curDisplayFilter {
		log.Infof("No operation - same pcap and filter.")
		fn()
	} else if c.State() == 0 {
		handleClear(cb)
		handleNewSource(cb)

		c.startLoadNewFile(pcap, curDisplayFilter, cb)

		c.When(func() bool {
			return c.State()&LoadingPsml == LoadingPsml
		}, fn)

		c.SetState(c.State() | LoadingPsml)
	} else {

		// First, wait until everything is stopped
		c.doStopLoadOperation(cb, func() {
			c.doLoadPcapOperation(pcap, displayFilter, cb, fn)
		})
	}
}

func (c *Loader) ReadingFromFifo() bool {
	// If it's a string it means that it's a filename, so it's not a fifo. Other values
	// in practise are the empty interface, or the read end of a fifo
	_, ok := c.PcapPsml.(string)
	return !ok
}

type unpackedHandlerFunc func(interface{}, ...chan struct{}) bool

func HandleUnpack(cb interface{}, handler unpackedHandlerFunc, chs ...chan struct{}) bool {
	if c, ok := cb.(IUnpack); ok {
		ch := getCbChan(chs...)
		var wg sync.WaitGroup
		handlers := c.Unpack()
		wg.Add(len(handlers))
		for _, cb := range handlers {
			cbcopy := cb // don't fall into loop variable non-capture trap
			termshark.TrackedGo(func() {
				ch2 := make(chan struct{})
				handler(cbcopy, ch2) // will wait on channel if it has to, doesn't matter if not
				wg.Done()
			}, Goroutinewg)
		}
		termshark.TrackedGo(func() {
			wg.Wait()
			close(ch)
		}, Goroutinewg)
		<-ch
		return true
	}
	return false
}

func getCbChan(chs ...chan struct{}) chan struct{} {
	if len(chs) > 0 {
		return chs[0]
	} else {
		return make(chan struct{})
	}
}

func HandleBegin(cb interface{}, chs ...chan struct{}) bool {
	res := false
	if !HandleUnpack(cb, HandleBegin) {
		if c, ok := cb.(IBeforeBegin); ok {
			ch := getCbChan(chs...)
			c.BeforeBegin(ch)
			<-ch
			res = true
		}
	}
	return res
}

func HandleEnd(cb interface{}, chs ...chan struct{}) bool {
	res := false
	if !HandleUnpack(cb, HandleEnd, chs...) {
		if c, ok := cb.(IAfterEnd); ok {
			ch := getCbChan(chs...)
			c.AfterEnd(ch)
			<-ch
			res = true
		}
	}
	return res
}

func HandleError(err error, cb interface{}, chs ...chan struct{}) bool {
	res := false
	if !HandleUnpack(cb, func(cb2 interface{}, chs2 ...chan struct{}) bool {
		return HandleError(err, cb2, chs2...)
	}, chs...) {
		if ec, ok := cb.(IOnError); ok {
			ch := getCbChan(chs...)
			ec.OnError(err, ch)
			<-ch
			res = true
		}
	}
	return res
}

func handleClear(cb interface{}, chs ...chan struct{}) bool {
	res := false
	if !HandleUnpack(cb, handleClear) {
		if c, ok := cb.(IClear); ok {
			ch := getCbChan(chs...)
			c.OnClear(ch)
			<-ch
			res = true
		}
	}
	return res
}

func handleNewSource(cb interface{}, chs ...chan struct{}) bool {
	res := false
	if !HandleUnpack(cb, handleNewSource) {
		if c, ok := cb.(INewSource); ok {
			ch := getCbChan(chs...)
			c.OnNewSource(ch)
			<-ch
			res = true
		}
	}
	return res
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

func (c *Loader) makeNewSourceContext() {
	c.thisSrcCtx, c.thisSrcCancelFn = context.WithCancel(c.mainCtx)
}

// Save the file first
// Always called from app goroutine context - so don't need to protect for race on cancelfn
// Assumes gstate is ready
// iface can be a number, or a fifo, or a pipe...
func (c *Loader) startLoadInterfacesNew(psrcs []IPacketSource, captureFilter string, displayFilter string, tmpfile string, cb interface{}) error {
	c.PcapPsml = nil
	c.PcapPdml = tmpfile
	c.PcapPcap = tmpfile

	c.psrcs = psrcs // dpm't know if it's fifo (tfifo), pipe (/dev/fd/3) or iface (eth0). Treated same way
	c.ifaceFile = tmpfile
	c.displayFilter = displayFilter
	c.captureFilter = captureFilter

	c.makeNewSourceContext()

	// It's a temporary unique file, and no processes are started yet, so either
	// (a) it doesn't exist, OR
	// (b) it does exist in which case this load is a result of a restart.
	// In ths second case, we need to discard existing packets before starting
	// tail in case it catches this file with existing data.
	err := os.Remove(tmpfile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	log.Infof("Starting new interface/fifo load '%v'", SourcesString(psrcs))
	c.startLoadPsml(cb)
	termshark.TrackedGo(func() {
		c.loadIfacesAsync(cb)
	}, Goroutinewg)

	return nil
}

func (c *Loader) startLoadNewFilter(displayFilter string, cb interface{}) {
	c.displayFilter = displayFilter

	c.makeNewSourceContext()

	log.Infof("Applying new display filter '%s'", displayFilter)
	c.startLoadPsml(cb)
}

func (c *Loader) clearSource() {
	c.psrcs = make([]IPacketSource, 0)
	c.ifaceFile = ""
	c.PcapPsml = ""
	c.PcapPdml = ""
	c.PcapPcap = ""
}

func (c *Loader) startLoadNewFile(pcap string, displayFilter string, cb interface{}) {
	c.psrcs = []IPacketSource{FileSource{Filename: pcap}}
	c.ifaceFile = ""

	c.PcapPsml = pcap
	c.PcapPdml = pcap
	c.PcapPcap = pcap
	c.displayFilter = displayFilter

	c.makeNewSourceContext()

	log.Infof("Starting new pcap file load '%s'", pcap)
	c.startLoadPsml(cb)
}

func (c *Loader) startLoadPsml(cb interface{}) {
	c.Lock()
	c.PacketCache.Purge()
	c.Unlock()

	termshark.TrackedGo(func() {
		c.loadPsmlAsync(cb)
	}, Goroutinewg)
}

// assumes no pcap is being loaded
func (c *Loader) startLoadPdml(row int, cb interface{}) {
	c.Lock()
	c.RowCurrentlyLoading = row
	c.Unlock()

	termshark.TrackedGo(func() {
		c.loadPcapAsync(row, cb)
	}, Goroutinewg)
}

// if done==true, then this cache entry is complete
func (c *Loader) updateCacheEntryWithPdml(row int, pdml []IPdmlPacket, done bool) {
	var ce CacheEntry
	c.Lock()
	defer c.Unlock()
	if ce2, ok := c.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pdml = pdml
	ce.PdmlComplete = done
	c.PacketCache.Add(row, ce)
}

func (c *Loader) updateCacheEntryWithPcap(row int, pcap [][]byte, done bool) {
	var ce CacheEntry
	c.Lock()
	defer c.Unlock()
	if ce2, ok := c.PacketCache.Get(row); ok {
		ce = ce2.(CacheEntry)
	}
	ce.Pcap = pcap
	ce.PcapComplete = done
	c.PacketCache.Add(row, ce)
}

func (c *Loader) LengthOfPdmlCacheEntry(row int) (int, error) {
	c.Lock()
	defer c.Unlock()
	if ce, ok := c.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pdml), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

func (c *Loader) LengthOfPcapCacheEntry(row int) (int, error) {
	c.Lock()
	defer c.Unlock()
	if ce, ok := c.PacketCache.Get(row); ok {
		ce2 := ce.(CacheEntry)
		return len(ce2.Pcap), nil
	}
	return -1, fmt.Errorf("No cache entry found for row %d", row)
}

type ISimpleCache interface {
	Complete() bool
}

var _ ISimpleCache = CacheEntry{}

type iPcapLoader interface {
	Interfaces() []string
	InterfaceFile() string
	DisplayFilter() string
	CaptureFilter() string
	NumLoaded() int
	CacheAt(int) (ISimpleCache, bool)
	LoadingRow() int
}

var _ iPcapLoader = (*Loader)(nil)
var _ fmt.Stringer = (*Loader)(nil)

func (c *Loader) String() string {
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

func (c *Loader) Pcap() string {
	for _, psrc := range c.psrcs {
		if psrc != nil && psrc.IsFile() {
			return psrc.Name()
		}
	}
	return ""
}

func (c *Loader) Interfaces() []string {
	names := make([]string, 0, len(c.psrcs))
	for _, psrc := range c.psrcs {
		if psrc != nil && !psrc.IsFile() {
			names = append(names, psrc.Name())
		}
	}
	return names
}

func (c *Loader) InterfaceFile() string {
	return c.ifaceFile
}

func (c *Loader) DisplayFilter() string {
	return c.displayFilter
}

func (c *Loader) CaptureFilter() string {
	return c.captureFilter
}

func (c *Loader) NumLoaded() int {
	c.Lock()
	defer c.Unlock()
	return len(c.PacketPsmlData)
}

func (c *Loader) LoadingRow() int {
	c.Lock()
	defer c.Unlock()
	return c.RowCurrentlyLoading
}

func (c *Loader) CacheAt(row int) (ISimpleCache, bool) {
	if ce, ok := c.PacketCache.Get(row); ok {
		return ce.(CacheEntry), ok
	}
	return CacheEntry{}, false
}

func (c *Loader) loadIsNecessary(ev LoadPcapSlice) bool {
	res := true
	if ev.Row > c.NumLoaded() {
		res = false
	} else if ce, ok := c.CacheAt((ev.Row / c.opt.PacketsPerLoad) * c.opt.PacketsPerLoad); ok && ce.Complete() {
		// Might be less because a cache load might've been interrupted - if it's not truncated then
		// we're set
		res = false
	} else if c.LoadingRow() == ev.Row {
		res = false
	}
	return res
}

func (c *Loader) signalStage2Done(cb interface{}) {
	c.Lock()
	ch := c.Stage2FinishedChan
	c.Stage2FinishedChan = make(chan struct{})
	c.Unlock()
	HandleEnd(cb, ch)
}

func (c *Loader) signalStage2Starting(cb interface{}) {
	HandleBegin(cb)
}

// Call from any goroutine - avoid calling in render, don't block it
// Procedure:
// - caller passes context, keeps cancel function
// - create a derived context for pcap reading processes
// - run them in goroutines
//   - for each pcap process,
//     - defer signal pcapchan when done
//     - check for ctx2.Err to break
//     - if err, then break
// - run goroutine to update UI with latest data on ticker
//   - if ctxt2 done, then break
// - run controller watching for
//   - if original ctxt done, then break (ctxt2 automatically cancelled)
//   - if both processes done, then
//     - cancel ticker with ctxt2
//   - wait for all to shut down
//   - final UI update
//func loadPcapAsync(ctx context.Context, pcapFile string, filter string, app gowid.IApp) error {
func (c *Loader) loadPcapAsync(row int, cb interface{}) {

	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	c.Lock()
	c.stage2Ctx, c.stage2CancelFn = context.WithCancel(c.thisSrcCtx)
	c.Unlock()

	intStage2Ctx, intStage2CancelFn := context.WithCancel(context.Background())

	// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
	var stageIsCancelled int32
	c.startPdmlChan = make(chan struct{})
	c.startPcapChan = make(chan struct{})

	// Returns true if it's an error we should bring to user's attention
	unexpectedError := func(err error) bool {
		cancelled := atomic.LoadInt32(&stageIsCancelled)
		if cancelled == 0 {
			if err != io.EOF {
				if err, ok := err.(*xml.SyntaxError); !ok || err.Msg != "unexpected EOF" {
					return true
				}
			}
		}
		return false
	}

	setCancelled := func() {
		atomic.CompareAndSwapInt32(&stageIsCancelled, 0, 1)
	}

	//======================================================================

	var displayFilterStr string

	sidx := -1
	eidx := -1

	// When we start a command (in service of loading pcaps), add it to this list. Then we wait
	// for finished signals on a channel -
	//procs := []ICommand{}

	// signal to updater that we're about to start. This will block until cb completes
	c.signalStage2Starting(cb)

	// This should correctly wait for all resources, no matter where in the process of creating them
	// an interruption or error occurs
	defer func() {
		procsDoneCount := 0
	L:
		for {
			// pdml and psml make 2
			select {
			// Don't need to wait for ctx.Done. if that gets cancelled, then it will propagate
			// to context2. The two tshark processes will wait on context2.Done, and complete -
			// then their defer blocks will send procDoneChan messages. When the count hits 2, this
			// select block will exit. Note that we also issue a cancel if count==2 because it might
			// just be that the tshark processes finish normally - then we need to stop the other
			// goroutines using ctxt2.
			case <-c.stage2GoroutineDoneChan:
				procsDoneCount++
				if procsDoneCount == 2 {
					intStage2CancelFn() // stop the ticker
					break L
				}
			}
		}

		// Wait for all other goroutines to complete
		c.stage2Wg.Wait()

		c.Lock()
		c.RowCurrentlyLoading = -1
		c.Unlock()

		c.signalStage2Done(cb)
	}()

	//
	// Goroutine to set mapping between table rows and frame numbers
	//
	termshark.TrackedGo(func() {
		select {
		case <-c.StartStage2Chan:
			break
		case <-c.stage2Ctx.Done():
			setCancelled()
			return
		case <-intStage2Ctx.Done():
			return // shutdown signalled - don't start the pdml/pcap processes
		}

		// Do this - but if we're cancelled first (stage2Ctx.Done), then they
		// don't need to be signalled because the other selects waiting on these
		// channels will be cancelled too.
		defer func() {
			// Signal the pdml and pcap reader to start.
			for _, ch := range []chan struct{}{c.startPdmlChan, c.startPcapChan} {
				select {
				case <-ch: // it will be closed if the psml has loaded already, and this e.g. a cached load
				default:
					close(ch)
				}
			}
		}()

		// If there's no filter, psml, pdml and pcap run concurrently for speed. Therefore the pdml and pcap
		// don't know how large the psml will be. So we set numToRead to 1000. This might be too high, but
		// we only use this to determine when we can kill the reading processes early. The result will be
		// correct if we don't kill the processes, it just might load for longer.
		c.KillAfterReadingThisMany = c.opt.PacketsPerLoad
		var err error
		if c.displayFilter == "" {
			sidx = row + 1
			// +1 for frame.number being 1-based; +1 to read past the end so that
			// the XML decoder doesn't stall and I can kill after abcdex
			eidx = row + c.opt.PacketsPerLoad + 1 + 1
		} else {
			c.Lock()
			if len(c.PacketPsmlData) > row {
				sidx, err = strconv.Atoi(c.PacketPsmlData[row][0])
				if err != nil {
					log.Fatal(err)
				}
				if len(c.PacketPsmlData) > row+c.opt.PacketsPerLoad+1 {
					// If we have enough packets to request one more than the amount to
					// cache, then requesting one more will mean the XML decoder won't
					// block at packet 999 waiting for </pdml> - so this is a hack to
					// let me promptly kill tshark when I've read enough.
					eidx, err = strconv.Atoi(c.PacketPsmlData[row+c.opt.PacketsPerLoad+1][0])
					if err != nil {
						log.Fatal(err)
					}
				} else {
					eidx, err = strconv.Atoi(c.PacketPsmlData[len(c.PacketPsmlData)-1][0])
					if err != nil {
						log.Fatal(err)
					}
					eidx += 1 // beyond end of last frame
					c.KillAfterReadingThisMany = len(c.PacketPsmlData) - row
				}
			}
			c.Unlock()
		}

		if c.displayFilter != "" {
			displayFilterStr = fmt.Sprintf("(%s) and (frame.number >= %d) and (frame.number < %d)", c.displayFilter, sidx, eidx)
		} else {
			displayFilterStr = fmt.Sprintf("(frame.number >= %d) and (frame.number < %d)", sidx, eidx)
		}

	}, &c.stage2Wg, Goroutinewg)

	//======================================================================

	//
	// Goroutine to run pdml process
	//
	termshark.TrackedGo(func() {
		defer func() {
			c.stage2GoroutineDoneChan <- struct{}{}
		}()

		// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
		// quit if that happens first
		select {
		case <-c.startPdmlChan:
		case <-c.stage2Ctx.Done():
			setCancelled()
			return
		case <-intStage2Ctx.Done():
			return
		}

		c.Lock()
		c.PdmlCmd = c.cmds.Pdml(c.PcapPdml, displayFilterStr)
		c.Unlock()

		pdmlOut, err := c.PdmlCmd.StdoutReader()
		if err != nil {
			HandleError(err, cb)
			return
		}

		err = c.PdmlCmd.Start()
		if err != nil {
			err = fmt.Errorf("Error starting PDML process %v: %v", c.PdmlCmd, err)
			HandleError(err, cb)
			return
		}

		log.Infof("Started PDML command %v with pid %d", c.PdmlCmd, c.PdmlCmd.Pid())

		defer func() {
			c.PdmlCmd.Wait()
		}()

		d := xml.NewDecoder(pdmlOut)
		packets := make([]IPdmlPacket, 0, c.opt.PacketsPerLoad)
		issuedKill := false
		var packet PdmlPacket
		var cpacket IPdmlPacket
	Loop:
		for {
			tok, err := d.Token()
			if err != nil {
				if unexpectedError(err) {
					err = fmt.Errorf("Could not read PDML data: %v", err)
					HandleError(err, cb)
				}
				break
			}
			switch tok := tok.(type) {
			case xml.StartElement:
				switch tok.Name.Local {
				case "packet":
					err := d.DecodeElement(&packet, &tok)
					if err != nil {
						if !issuedKill && unexpectedError(err) {
							err = fmt.Errorf("Could not decode PDML data: %v", err)
							HandleError(err, cb)
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
					c.updateCacheEntryWithPdml(row, packets, false)
					//if len(pdml2) == abcdex {
					if len(packets) == c.KillAfterReadingThisMany {
						// Shortcut - we never take more than abcdex - so just kill here
						issuedKill = true
						err = termshark.KillIfPossible(c.PdmlCmd)
						if err != nil {
							log.Infof("Did not kill pdml process: %v", err)
						}
					}
				}

			}

		}

		// Want to preserve invariant - for simplicity - that we only add full loads
		// to the cache
		cancelled := atomic.LoadInt32(&stageIsCancelled)
		if cancelled == 0 {
			// never evict row 0
			c.PacketCache.Get(0)
			c.Lock()
			if c.highestCachedRow != -1 {
				// try not to evict "end"
				c.PacketCache.Get(c.highestCachedRow)
			}
			c.Unlock()

			// the cache entry is marked complete if we are not reading from a fifo, which implies
			// the source of packets will not grow larger. If it could grow larger, we want to ensure
			// that termshark doesn't think that there are only 900 packets, because that's what's
			// in the cache from a previous request - now there might be 950 packets.
			c.updateCacheEntryWithPdml(row, packets, !c.ReadingFromFifo())
			if row > c.highestCachedRow {
				c.Lock()
				c.highestCachedRow = row
				c.Unlock()
			}
		}
	}, &c.stage2Wg, Goroutinewg)

	//======================================================================

	//
	// Goroutine to run pcap process
	//
	termshark.TrackedGo(func() {
		defer func() {
			c.stage2GoroutineDoneChan <- struct{}{}
		}()

		// Wait for stage 2 to be kicked off (potentially by psml load, then mapping table row to frame num); or
		// quit if that happens first
		select {
		case <-c.startPcapChan:
		case <-c.stage2Ctx.Done():
			setCancelled()
			return
		case <-intStage2Ctx.Done():
			return
		}

		c.Lock()
		c.PcapCmd = c.cmds.Pcap(c.PcapPcap, displayFilterStr)
		c.Unlock()

		pcapOut, err := c.PcapCmd.StdoutReader()
		if err != nil {
			HandleError(err, cb)
			return
		}

		err = c.PcapCmd.Start()
		if err != nil {
			// e.g. on the pi
			err = fmt.Errorf("Error starting PCAP process %v: %v", c.PcapCmd, err)
			HandleError(err, cb)
			return
		}

		log.Infof("Started pcap command %v with pid %d", c.PcapCmd, c.PcapCmd.Pid())

		defer func() {
			c.PcapCmd.Wait()
		}()

		packets := make([][]byte, 0, c.opt.PacketsPerLoad)
		issuedKill := false
		re := regexp.MustCompile(`([0-9a-f][0-9a-f] )`)
		rd := bufio.NewReader(pcapOut)
		packet := make([]byte, 0)

		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				if !issuedKill && unexpectedError(err) {
					err = fmt.Errorf("Could not read PCAP packet: %v", err)
					HandleError(err, cb)
				}
				break
			}

			parseResults := re.FindAllStringSubmatch(string(line), -1)

			if len(parseResults) < 1 {
				packets = append(packets, packet)
				packet = make([]byte, 0)

				readEnough := (len(packets) >= c.KillAfterReadingThisMany)
				c.updateCacheEntryWithPcap(row, packets, false)

				if readEnough {
					// Shortcut - we never take more than abcdex - so just kill here
					issuedKill = true
					err = termshark.KillIfPossible(c.PcapCmd)
					if err != nil {
						log.Infof("Did not kill pdml process: %v", err)
					}
				}
			} else {
				// Ignore line number
				for _, parsedByte := range parseResults[1:] {
					b, err := strconv.ParseUint(string(parsedByte[0][0:2]), 16, 8)
					if err != nil {
						err = fmt.Errorf("Could not read PCAP packet: %v", err)
						HandleError(err, cb)
						break
					}
					packet = append(packet, byte(b))
				}
			}
		}

		// I just want to ensure I read it from ram, obviously this is racey
		cancelled := atomic.LoadInt32(&stageIsCancelled)
		if cancelled == 0 {
			// never evict row 0
			c.PacketCache.Get(0)
			if c.highestCachedRow != -1 {
				// try not to evict "end"
				c.PacketCache.Get(c.highestCachedRow)
			}
			c.updateCacheEntryWithPcap(row, packets, !c.ReadingFromFifo())
		}

	}, &c.stage2Wg, Goroutinewg)

	//
	// Goroutine to track an external shutdown - kills processes in case the external
	// shutdown comes first. If it's an internal shutdown, no need to kill because
	// that would only be triggered once processes are dead
	//
	termshark.TrackedGo(func() {
		select {
		case <-c.stage2Ctx.Done():
			setCancelled()
			err := termshark.KillIfPossible(c.PcapCmd)
			if err != nil {
				log.Infof("Did not kill pcap process: %v", err)
			}
			err = termshark.KillIfPossible(c.PdmlCmd)
			if err != nil {
				log.Infof("Did not kill pdml process: %v", err)
			}
		case <-intStage2Ctx.Done():
		}
	}, Goroutinewg)
}

func (c *Loader) TurnOffPipe() {
	// Switch over to  the temp pcap file. If a new filter is applied
	// after stopping, we should read from the temp file and not the fifo
	// because nothing will be feeding the fifo.
	if c.PcapPsml != c.PcapPdml {
		log.Infof("Switching from interface/fifo mode to file mode")
		c.PcapPsml = c.PcapPdml
	}
}

func (c *Loader) signalPsmlStarting(cb interface{}) {
	HandleBegin(cb)
}

func (c *Loader) signalPsmlDone(cb interface{}) {
	ch := c.PsmlFinishedChan
	c.PsmlFinishedChan = make(chan struct{})
	HandleEnd(cb, ch)
}

// Holds a reference to the loader, and wraps Read() around the tail process's
// Read(). Count the bytes, and when they are equal to the final total of bytes
// written by the tshark -i process (spooling to a tmp file), a function is called
// which stops the PSML process.
type tailReadTracker struct {
	tailReader io.Reader
	loader     *Loader
	callback   interface{}
}

func (r *tailReadTracker) Read(p []byte) (int, error) {
	n, err := r.tailReader.Read(p)
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

	r.loader.checkAllBytesRead(r.callback)

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
func (c *Loader) checkAllBytesRead(cb interface{}) {
	cancel := false
	if !c.totalFifoBytesWritten.IsNone() && !c.totalFifoBytesRead.IsNone() {
		if c.totalFifoBytesRead.Val() == c.totalFifoBytesWritten.Val() {
			cancel = true
		}
	}
	if c.fifoError != nil {
		cancel = true
	}

	// if there was a fifo error, OR we have read all the bytes that were written, then
	// we need to stop the tail command
	if cancel {
		if c.fifoError != nil {
			err := fmt.Errorf("Fifo error: %v", c.fifoError)
			HandleError(err, cb)
		}
		if c.tailCmd != nil {
			c.totalFifoBytesWritten = gwutil.NoneInt64()
			c.totalFifoBytesRead = gwutil.NoneInt64()

			err := termshark.KillIfPossible(c.tailCmd)
			if err != nil {
				log.Infof("Did not kill tail process: %v", err)
			} else {
				c.tailCmd.Wait() // this will block the exit of this function until the command is killed

				// We need to explicitly close the write side of the pipe. Without this,
				// the PSML process Wait() function won't complete, because golang won't
				// complete termination until IO has finished, and io.Copy() will be stuck
				// in a loop.
				c.tailCmd.Close()
			}
		}
	}
}

func (c *Loader) loadPsmlAsync(cb interface{}) {
	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	c.psmlCtx, c.psmlCancelFn = context.WithCancel(c.thisSrcCtx)

	intPsmlCtx, intPsmlCancelFn := context.WithCancel(context.Background())

	// signalling psml done to the goroutine that started

	//======================================================================

	// Make sure data is cleared before we signal we're starting. This gives callbacks a clean
	// view, not the old view of a loader with old data.
	c.Lock()
	c.PacketPsmlData = make([][]string, 0)
	c.PacketPsmlColors = make([]PacketColors, 0)
	c.PacketPsmlHeaders = make([]string, 0, 10)
	c.PacketNumberMap = make(map[int]int)
	c.PacketCache.Purge()
	c.LoadWasCancelled = false
	c.StartStage2Chan = make(chan struct{}) // do this before signalling start
	c.Unlock()

	// signal to updater that we're about to start. This will block until cb completes
	c.signalPsmlStarting(cb)

	defer func() {
		c.signalPsmlDone(cb)
	}()

	//======================================================================

	var psmlOut io.ReadCloser

	// Only start this process if we are in interface mode
	var err error
	var pr *os.File
	var pw *os.File

	//======================================================================

	// Make sure we start the goroutine that monitors for shutdown early - so if/when
	// a shutdown happens, and we get blocked in the XML parser, this will be able to
	// respond

	termshark.TrackedGo(func() {
		select {
		case <-c.psmlCtx.Done():
			intPsmlCancelFn() // start internal shutdown
		case <-intPsmlCtx.Done():
		}

		if c.tailCmd != nil {
			err := termshark.KillIfPossible(c.tailCmd)
			if err != nil {
				log.Infof("Did not kill tail process: %v", err)
			}
		}

		if c.PsmlCmd != nil {
			err := termshark.KillIfPossible(c.PsmlCmd)
			if err != nil {
				log.Infof("Did not kill psml process: %v", err)
			}
		}

		if psmlOut != nil {
			psmlOut.Close() // explicitly close else this goroutine can block
		}

	}, Goroutinewg)

	//======================================================================

	// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
	if c.displayFilter == "" || c.ReadingFromFifo() {
		// don't hold up pdml and pcap generators. If the filter is "", then the frame numbers
		// equal the row numbers, so we don't need the psml to map from row -> frame.
		//
		// And, if we are in interface mode, we won't reach the end of the psml anyway.
		//
		close(c.StartStage2Chan)
	}

	//======================================================================

	closePipe := func() {
		if pw != nil {
			pw.Close()
			pw = nil
		}
		if pr != nil {
			pr.Close()
			pr = nil
		}
	}

	if c.ReadingFromFifo() {
		// PcapPsml will be nil if here

		// Build a pipe - the side to be read from will be given to the PSML process
		// and the side to be written to is given to the tail process, which feeds in
		// data from the pcap source.
		//
		pr, pw, err = os.Pipe()
		if err != nil {
			err = fmt.Errorf("Could not create pipe: %v", err)
			HandleError(err, cb)
			intPsmlCancelFn()
			return
		}
		// pw is used as Stdout for the tail command, which unwinds in this
		// goroutine - so we can close at this point in the unwinding. pr
		// is used as stdin for the psml command, which also runs in this
		// goroutine.
		defer closePipe()

		// wrap the read end of the pipe with a Read() function that counts
		// bytes. If they are equal to the total bytes written to the tmpfile by
		// the tshark -i process, then that means the source is exhausted, and
		// the tail + psml processes are stopped.
		c.PcapPsml = &tailReadTracker{
			tailReader: pr,
			loader:     c,
			callback:   cb,
		}
	}

	c.Lock()
	c.PsmlCmd = c.cmds.Psml(c.PcapPsml, c.displayFilter)
	c.Unlock()

	psmlOut, err = c.PsmlCmd.StdoutReader()
	if err != nil {
		err = fmt.Errorf("Could not access pipe output: %v", err)
		HandleError(err, cb)
		intPsmlCancelFn()
		return
	}

	err = c.PsmlCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting PSML command %v: %v", c.PsmlCmd, err)
		HandleError(err, cb)
		intPsmlCancelFn()
		return
	}

	log.Infof("Started PSML command %v with pid %d", c.PsmlCmd, c.PsmlCmd.Pid())

	defer func() {
		// These need to close so the tailreader Read() terminates so that the
		// PsmlCmd.Wait() below completes.
		closePipe()
		err := c.PsmlCmd.Wait()
		if !c.SuppressErrors {
			if err != nil {
				if _, ok := err.(*exec.ExitError); ok {
					cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
						"command": c.PsmlCmd.String(),
						"error":   err,
					})
					HandleError(cerr, cb)
				}
			}
			// If the psml command generates an error, then we should stop any feed
			// from the interface too.
			c.stopLoadIface()
		}
	}()

	//======================================================================

	// If it was cancelled, then we don't need to start the tail process because
	// psml will read from the tmp pcap file generated by the interface reading
	// process.

	c.tailCmd = nil

	if c.ReadingFromFifo() {
		c.tailCmd = c.cmds.Tail(c.ifaceFile)
		c.tailCmd.SetStdout(pw)

		// this set up is so that I can detect when there are actually packets to read (e.g
		// maybe there's no traffic on the interface). When there's something to read, the
		// rest of the procedure can spring into action.
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			err = fmt.Errorf("Could not create FS watch: %v", err)
			HandleError(err, cb)
			intPsmlCancelFn()
			return
		}
		defer watcher.Close()

		if err := watcher.Add(filepath.Dir(c.ifaceFile)); err != nil {
			err = fmt.Errorf("Could not set up watcher for %s: %v", c.ifaceFile, err)
			HandleError(err, cb)
			intPsmlCancelFn()
			return
		} else {
			// If it's there, touch it so watcher below is notified that everything is in order
			if _, err := os.Stat(c.ifaceFile); err == nil {
				if err = os.Chtimes(c.ifaceFile, time.Now(), time.Now()); err != nil {
					HandleError(err, cb)
					intPsmlCancelFn()
					return
				}
			}

		}

		defer func() {
			watcher.Remove(filepath.Dir(c.ifaceFile))
		}()

	Loop:
		for {
			select {
			case fe := <-watcher.Events:
				if fe.Name == c.ifaceFile {
					break Loop
				}
			case err := <-watcher.Errors:
				err = fmt.Errorf("Unexpected watcher error for %s: %v", c.ifaceFile, err)
				HandleError(err, cb)
				intPsmlCancelFn()
				return
			case <-intPsmlCtx.Done():
				return
			}
		}

		log.Infof("Starting Tail command: %v", c.tailCmd)

		err = c.tailCmd.Start()
		if err != nil {
			err = fmt.Errorf("Could not start tail command %v: %v", c.tailCmd, err)
			HandleError(err, cb)
			intPsmlCancelFn()
			return
		}

		// Do this in a goroutine - in a defer, it would block here before the code executes
		defer func() {
			c.tailCmd.Wait() // this will block the exit of this function until the command is killed

			// We need to explicitly close the write side of the pipe. Without this,
			// the PSML process Wait() function won't complete, because golang won't
			// complete termination until IO has finished, and io.Copy() will be stuck
			// in a loop.
			pw.Close()
		}()
	}

	//======================================================================

	//
	// Goroutine to read psml xml and update data structures
	//
	defer func() {
		select {
		case <-c.StartStage2Chan:
			// already done/closed, do nothing
		default:
			close(c.StartStage2Chan)
		}

		// This will kill the tail process if there is one
		intPsmlCancelFn() // stop the ticker
	}()

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
	var fg string
	var bg string
	var pidx int
	ready := false
	empty := true
	structure := false
	for {
		if intPsmlCtx.Err() != nil {
			break
		}
		tok, err := d.Token()
		if err != nil {
			if err != io.EOF && !c.LoadWasCancelled {
				err = fmt.Errorf("Could not read PSML data: %v", err)
				HandleError(err, cb)
			}
			break
		}
		switch tok := tok.(type) {
		case xml.EndElement:
			switch tok.Name.Local {
			case "structure":
				structure = false
			case "packet":
				c.Lock()
				c.PacketPsmlData = append(c.PacketPsmlData, curPsml)

				// Track the mapping of packet number <section>12</section> to position
				// in the table e.g. 5th element. This is so that I can jump to the correct
				// row with marks even if a filter is currently applied.
				pidx, err = strconv.Atoi(curPsml[0])
				if err != nil {
					log.Fatal(err)
				}
				c.PacketNumberMap[pidx] = len(c.PacketPsmlData) - 1

				c.PacketPsmlColors = append(c.PacketPsmlColors, PacketColors{
					FG: psmlColorToIColor(fg),
					BG: psmlColorToIColor(bg),
				})
				c.Unlock()

			case "section":
				ready = false
				// Means we got </section> without any char data i.e. empty <section>
				if empty {
					curPsml = append(curPsml, "")
				}
			}
		case xml.StartElement:
			switch tok.Name.Local {
			case "structure":
				structure = true
			case "packet":
				curPsml = make([]string, 0, 10)
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
					c.Lock()
					c.PacketPsmlHeaders = append(c.PacketPsmlHeaders, string(tok))
					c.Unlock()
				} else {
					curPsml = append(curPsml, string(format.TranslateHexCodes(tok)))
					empty = false
				}
			}
		}
	}
}

// dumpcap -i eth0 -w /tmp/foo.pcap
// dumpcap -i /dev/fd/3 -w /tmp/foo.pcap
func (c *Loader) loadIfacesAsync(cb interface{}) {
	c.totalFifoBytesWritten = gwutil.NoneInt64()
	c.ifaceCtx, c.ifaceCancelFn = context.WithCancel(c.thisSrcCtx)

	defer func() {
		ch := c.IfaceFinishedChan
		c.IfaceFinishedChan = make(chan struct{})
		close(ch)
		c.ifaceCtx = nil
		c.ifaceCancelFn = nil
	}()

	c.ifaceCmd = c.cmds.Iface(SourcesNames(c.psrcs), c.captureFilter, c.ifaceFile)

	log.Infof("Starting Iface command: %v", c.ifaceCmd)

	err := c.ifaceCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting interface reader %v: %v", c.ifaceCmd, err)
		HandleError(err, cb)
		return
	}

	termshark.TrackedGo(func() {
		// Wait for external cancellation. This is the shutdown procedure.
		<-c.ifaceCtx.Done()
		err := termshark.KillIfPossible(c.ifaceCmd)
		if err != nil {
			log.Infof("Did not kill iface reader process: %v", err)
		}
	}, Goroutinewg)

	defer func() {
		// if psrc is a PipeSource, then we open /dev/fd/3 in termshark, and reroute descriptor
		// stdin to number 3 when termshark starts. So to kill the process writing in, we need
		// to close our side of the pipe.
		for _, psrc := range c.psrcs {
			if cl, ok := psrc.(io.Closer); ok {
				cl.Close()
			}
		}
	}()

	err = c.ifaceCmd.Wait() // it definitely started, so we must wait
	if !c.SuppressErrors && err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// This could be if termshark is started like this: cat nosuchfile.pcap | termshark -i -
			// Then dumpcap will be started with /dev/fd/3 as its stdin, but will fail with EOF and
			// exit status 1.
			cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
				"command": c.ifaceCmd.String(),
				"error":   err,
			})
			HandleError(cerr, cb)
		}
	}

	// If something killed it, then start the internal shutdown procedure anyway to clean up
	// goroutines waiting on the context. This could also happen if tshark -i is reading from
	// a fifo and the write has stopped e.g.
	//
	// cat foo.pcap > myfifo
	// termshark -i myfifo
	//
	// termshark will get EOF when the cat terminates (if there are no more writers).
	//

	// Calculate the final size of the tmp file we wrote with packets read from the
	// interface/pipe. This runs after the dumpcap command finishes.
	fi, err := os.Stat(c.ifaceFile)
	if err != nil {
		log.Warn(err)
		// Deliberately not a fatal error - it can happen if the source of packets to tshark -i
		// is corrupt, resulting in a tshark error. Setting zero here will line up with the
		// reading end which will read zero, and so terminate the tshark -T psml procedure.

		if c.fifoError == nil && !os.IsNotExist(err) {
			// Ignore ENOENT because it means there was an error before dumpcap even wrote
			// anything to disk
			c.fifoError = err
		}
	} else {
		c.totalFifoBytesWritten = gwutil.SomeInt64(fi.Size())
	}

	c.checkAllBytesRead(cb)

	c.ifaceCancelFn()
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
	Row    int
	Cancel bool
}

func (m *LoadPcapSlice) String() string {
	if m.Cancel {
		return fmt.Sprintf("[loadslice: %d, cancel: %v]", m.Row, m.Cancel)
	} else {
		return fmt.Sprintf("[loadslice: %d]", m.Row)
	}
}

//======================================================================

type ICacheUpdater interface {
	WhenLoadingPdml()
	WhenNotLoadingPdml()
}

type ICacheLoader interface {
	State() LoaderState
	SetState(LoaderState)
	loadIsNecessary(ev LoadPcapSlice) bool
	stopLoadPdml()
	startLoadPdml(int, interface{})
}

func ProcessPdmlRequests(requests []LoadPcapSlice, loader ICacheLoader, updater ICacheUpdater) []LoadPcapSlice {
Loop:
	for {
		if len(requests) == 0 {
			break
		} else {
			ev := requests[0]

			if loader.loadIsNecessary(ev) {
				if loader.State()&LoadingPdml != 0 {
					// we are loading a piece. Do we need to cancel? If not, reschedule for when idle
					if ev.Cancel {
						loader.stopLoadPdml()
					}
					updater.WhenNotLoadingPdml()
				} else {
					loader.startLoadPdml(ev.Row, updater)
					loader.SetState(loader.State() | LoadingPdml)
					updater.WhenLoadingPdml()
				}
				break Loop
			} else {
				requests = requests[1:]
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

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
