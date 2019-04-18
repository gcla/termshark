// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gcla/termshark"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify.v1"
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

type ICommand interface {
	Start() error
	Wait() error
	Kill() error
	StdoutPipe() (io.ReadCloser, error)
	SetStdout(io.Writer)
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
	Start() error
	Wait() error
	Pid() int
	Kill() error
}

type ITailCommand interface {
	IBasicCommand
	SetStdout(io.Writer)
}

type IPcapCommand interface {
	IBasicCommand
	StdoutPipe() (io.ReadCloser, error)
}

type ILoaderCmds interface {
	Iface(iface string, captureFilter string, tmpfile string) IBasicCommand
	Tail(tmpfile string) ITailCommand
	Psml(pcap interface{}, displayFilter string) IPcapCommand
	Pcap(pcap string, displayFilter string) IPcapCommand
	Pdml(pcap string, displayFilter string) IPcapCommand
}

type Loader struct {
	cmds ILoaderCmds

	state LoaderState // which pieces are currently loading

	pcap          string // The pcap source for this loader, "" if the loader is based on an interface
	iface         string // The interface being read from, "" if the loader is based on a pcap file
	ifaceFile     string // The temp pcap file that is created by reading from the interface
	displayFilter string
	captureFilter string

	PcapPsml interface{} // Pcap file source for the psml reader - fifo if iface+!stopped; tmpfile if iface+stopped; pcap otherwise
	PcapPdml string      // Pcap file source for the pdml reader - tmpfile if iface; pcap otherwise
	PcapPcap string      // Pcap file source for the pcap reader - tmpfile if iface; pcap otherwise

	mainCtx        context.Context // cancelling this cancels the dependent contexts
	mainCancelFn   context.CancelFunc
	psmlCtx        context.Context // cancels the psml loading process
	psmlCancelFn   context.CancelFunc
	stage2Ctx      context.Context // cancels the pcap/pdml loading process
	stage2CancelFn context.CancelFunc
	ifaceCtx       context.Context // cancels the iface reader process
	ifaceCancelFn  context.CancelFunc

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
	PacketPsmlHeaders []string
	PacketCache       *lru.Cache // i -> [pdml(i * 1000)..pdml(i+1*1000)]

	onStateChange []runFnInState

	LoadWasCancelled         bool // True if the last load (iface or file) was halted by the stop button
	RowCurrentlyLoading      int  // set by the pdml loading stage
	highestCachedRow         int
	KillAfterReadingThisMany int // A shortcut - tell pcap/pdml to read one

	opt Options
}

type Options struct {
	CacheSize int
}

func NewPcapLoader(cmds ILoaderCmds, opts ...Options) *Loader {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.CacheSize == 0 {
		opt.CacheSize = 32
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
	c.PacketPsmlHeaders = make([]string, 0, 10)
	packetCache, err := lru.New(c.opt.CacheSize)
	if err != nil {
		log.Fatal(err)
	}
	c.PacketCache = packetCache
}

// Close shuts down the whole loader, including progress monitoring goroutines. Use this only
// when about to load a new pcap (use a new loader)
func (c *Loader) Close() error {
	if c.mainCancelFn != nil {
		c.mainCancelFn()
	}
	return nil
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
}

func (c *Scheduler) Disable() {
	c.disabled = true
}

func (c *Scheduler) RequestClearPcap(cb interface{}) {
	c.OperationsChan <- func() {
		c.Disable()
		c.doClearPcapOperation(cb, func() {
			c.Enable()
		})

	}
}

func (c *Scheduler) RequestStopLoad(cb interface{}) {
	c.OperationsChan <- func() {
		c.Disable()
		c.doStopLoadOperation(cb, func() {
			c.Enable()
		})
	}
}

func (c *Scheduler) RequestNewFilter(newfilt string, cb interface{}) {
	c.OperationsChan <- func() {
		c.Disable()
		c.doNewFilterOperation(newfilt, cb, c.Enable)
	}
}

func (c *Scheduler) RequestLoadInterface(iface string, captureFilter string, displayFilter string, cb interface{}) {
	c.OperationsChan <- func() {
		c.Disable()
		c.doLoadInterfaceOperation(iface, captureFilter, displayFilter, cb, func() {
			c.Enable()
		})
	}
}

func (c *Scheduler) RequestLoadPcap(pcap string, displayFilter string, cb interface{}) {
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
	//var res EnableOperationsWhen

	// if bb, ok := cb.(IBeforeBegin); ok {
	// 	ch := make(chan struct{})
	// 	bb.BeforeBegin(ch)
	// }

	if c.State() == 0 {
		c.resetData()

		if oc, ok := cb.(IClear); ok {
			ch := make(chan struct{})
			oc.OnClear(ch)
		}
		//cb.OnClear()

		fn()
	} else {
		// If we are reading from an interface when the clear operation is issued, we should
		// continue again afterwards. If we're reading from a file, the clear stops the read.
		// Track this state.
		startIfaceAgain := false

		if c.State()&LoadingIface != 0 {
			startIfaceAgain = true
			c.stopLoadIface()
		}

		if c.State()&LoadingPsml != 0 {
			c.stopLoadPsml()
		}

		c.When(c.IdleState, func() {
			// Document why this needs to be delayed again, since runWhenReadyFn
			// will run in app goroutine
			c.doClearPcapOperation(cb, func() {
				if startIfaceAgain {
					c.doLoadInterfaceOperation(c.Interface(), c.CaptureFilter(), c.DisplayFilter(), cb, fn)
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

	if bb, ok := cb.(IBeforeBegin); ok {
		ch := make(chan struct{})
		bb.BeforeBegin(ch)
	}

	if c.State() != 0 {
		c.stopLoadPsml()
		c.stopLoadPdml()
		c.stopLoadIface()

		c.When(c.IdleState, func() {
			c.doStopLoadOperation(cb, fn)
		})
	} else {
		c.turnOffPipe()
		fn()
		if aa, ok := cb.(IAfterEnd); ok {
			ch := make(chan struct{})
			aa.AfterEnd(ch)
		}
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

		c.When(func() bool {
			return c.State()&LoadingPsml == 0
		}, func() {
			c.doNewFilterOperation(newfilt, cb, fn)
		})
	}
}

type IClear interface {
	OnClear(closeMe chan<- struct{})
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

func (c *Loader) doLoadInterfaceOperation(iface string, captureFilter string, displayFilter string, cb interface{}, fn RunFn) {
	// The channel is unbuffered, and monitored from the same goroutine, so this would block
	// unless we start a new goroutine

	//var res EnableOperationsWhen

	// If we're already loading, but the request is for the same, then ignore. If we were stopped, then
	// process the request, because it implicitly means start reading from the interface again (and we
	// are stopped)
	if c.State()&LoadingPsml != 0 && c.Interface() == iface && c.DisplayFilter() == displayFilter && c.CaptureFilter() == captureFilter {
		log.Infof("No operation - same interface and filters.")
	} else if c.State() == 0 {
		if oc, ok := cb.(IClear); ok {
			ch := make(chan struct{})
			oc.OnClear(ch)
		}

		if err := c.startLoadInterfaceNew(iface, captureFilter, displayFilter, cb); err == nil {
			c.When(func() bool {
				return c.State()&(LoadingIface|LoadingPsml) == LoadingIface|LoadingPsml
			}, fn)

			c.SetState(c.State() | LoadingIface | LoadingPsml)
		} else {
			handleError(err, cb)
		}
	} else if c.State() == LoadingIface && iface == c.Interface() {
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
		if c.State()&LoadingIface != 0 && iface != c.Interface() {
			c.doStopLoadOperation(cb, func() {
				c.doLoadInterfaceOperation(iface, captureFilter, displayFilter, cb, fn)
			}) // returns an enable function when idle
		} else {
			c.doStopLoadToIfaceOperation(func() {
				c.doLoadInterfaceOperation(iface, captureFilter, displayFilter, cb, fn)
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
	} else if c.State() == 0 {
		handleClear(cb)

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
	return c.PcapPdml != c.PcapPsml
}

func handleBegin(cb interface{}) {
	if c, ok := cb.(IBeforeBegin); ok {
		ch := make(chan struct{})
		c.BeforeBegin(ch)
		<-ch
	}
}

func handleEnd(cb interface{}) {
	if c, ok := cb.(IAfterEnd); ok {
		ch := make(chan struct{})
		c.AfterEnd(ch)
		<-ch
	}
}

func handleError(err error, cb interface{}) {
	if ec, ok := cb.(IOnError); ok {
		ch := make(chan struct{})
		ec.OnError(err, ch)
		<-ch
	}
}

func handleClear(cb interface{}) {
	if c, ok := cb.(IClear); ok {
		ch := make(chan struct{})
		c.OnClear(ch)
		<-ch
	}
}

// Save the file first
// Always called from app goroutine context - so don't need to protect for race on cancelfn
// Assumes gstate is ready
func (c *Loader) startLoadInterfaceNew(iface string, captureFilter string, displayFilter string, cb interface{}) error {
	re := regexp.MustCompile(`[^a-zA-Z0-9.-]`)
	ifaceClean := re.ReplaceAllString(iface, "_")

	tmpfile, err := ioutil.TempFile(termshark.CacheDir(), fmt.Sprintf("%s-*.pcap", ifaceClean))
	if err != nil {
		handleError(err, cb)
		return err
	}
	err = tmpfile.Close()
	if err != nil {
		handleError(err, cb)
		return err
	}

	c.PcapPsml = nil
	c.PcapPdml = tmpfile.Name()
	c.PcapPcap = tmpfile.Name()

	c.pcap = ""
	c.iface = iface
	c.ifaceFile = tmpfile.Name()
	c.displayFilter = displayFilter
	c.captureFilter = captureFilter

	c.startLoadPsml(cb)
	termshark.TrackedGo(func() {
		c.loadIfaceAsync(cb)
	}, Goroutinewg)

	return nil
}

func (c *Loader) startLoadNewFilter(displayFilter string, cb interface{}) {
	c.displayFilter = displayFilter

	c.startLoadPsml(cb)
}

func (c *Loader) startLoadNewFile(pcap string, displayFilter string, cb interface{}) {
	c.pcap = pcap
	c.iface = ""
	c.ifaceFile = ""

	c.PcapPsml = pcap
	c.PcapPdml = pcap
	c.PcapPcap = pcap
	c.displayFilter = displayFilter

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
	c.RowCurrentlyLoading = row

	termshark.TrackedGo(func() {
		c.loadPcapAsync(row, cb)
	}, Goroutinewg)
}

func (c *Loader) updateCacheEntryWithPdml(row int, pdml []*PdmlPacket, done bool) {
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
	Interface() string
	DisplayFilter() string
	CaptureFilter() string
	NumLoaded() int
	CacheAt(int) (ISimpleCache, bool)
	LoadingRow() int
}

var _ iPcapLoader = (*Loader)(nil)

func (c *Loader) Pcap() string {
	return c.pcap
}

func (c *Loader) Interface() string {
	return c.iface
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

func (c *Loader) CacheAt(row int) (ISimpleCache, bool) {
	if ce, ok := c.PacketCache.Get(row); ok {
		return ce.(CacheEntry), ok
	}
	return CacheEntry{}, false
}

func (c *Loader) LoadingRow() int {
	return c.RowCurrentlyLoading
}

func (c *Loader) loadIsNecessary(ev LoadPcapSlice) bool {
	res := true
	if ev.Row > c.NumLoaded() {
		res = false
	} else if ce, ok := c.CacheAt((ev.Row / 1000) * 1000); ok && ce.Complete() {
		// Might be less because a cache load might've been interrupted - if it's not truncated then
		// we're set
		res = false
	} else if c.LoadingRow() == ev.Row {
		res = false
	}
	return res
}

func (c *Loader) signalStage2Done(cb interface{}) {
	ch := c.Stage2FinishedChan
	c.Stage2FinishedChan = make(chan struct{})
	if a, ok := cb.(IAfterEnd); ok {
		a.AfterEnd(ch)
		<-ch
	}
}

func (c *Loader) signalStage2Starting(cb interface{}) {
	handleBegin(cb)
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

	c.stage2Ctx, c.stage2CancelFn = context.WithCancel(c.mainCtx)

	intStage2Ctx, intStage2CancelFn := context.WithCancel(context.Background())

	// Set to true by a goroutine started within here if ctxCancel() is called i.e. the outer context
	var stageIsCancelled int32
	c.startPdmlChan = make(chan struct{})
	c.startPcapChan = make(chan struct{})

	// Returns true if it's an error we should bring to user's attention
	unexpectedError := func(err error) bool {
		cancelled := atomic.LoadInt32(&stageIsCancelled)
		if err != io.EOF && cancelled == 0 {
			return true
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

		// Safe, in goroutine thread
		c.RowCurrentlyLoading = -1

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
		c.KillAfterReadingThisMany = 1000
		var err error
		if c.displayFilter == "" {
			sidx = row + 1
			// +1 for frame.number being 1-based; +1 to read past the end so that
			// the XML decoder doesn't stall and I can kill after 1000
			eidx = row + 1000 + 1 + 1
		} else {
			c.Lock()
			if len(c.PacketPsmlData) > row {
				sidx, err = strconv.Atoi(c.PacketPsmlData[row][0])
				if err != nil {
					log.Fatal(err)
				}
				if len(c.PacketPsmlData) > row+1000+1 {
					// If we have enough packets to request one more than the amount to
					// cache, then requesting one more will mean the XML decoder won't
					// block at packet 999 waiting for </pdml> - so this is a hack to
					// let me promptly kill tshark when I've read enough.
					eidx, err = strconv.Atoi(c.PacketPsmlData[row+1000+1][0])
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

		c.PdmlCmd = c.cmds.Pdml(c.PcapPdml, displayFilterStr)

		pdmlOut, err := c.PdmlCmd.StdoutPipe()
		if err != nil {
			handleError(err, cb)
			return
		}

		log.Infof("Starting PDML command: %v", c.PdmlCmd)

		err = c.PdmlCmd.Start()
		if err != nil {
			err = fmt.Errorf("Error starting PDML process %v: %v", c.PdmlCmd, err)
			handleError(err, cb)
			return
		}

		defer func() {
			c.PdmlCmd.Wait()
		}()

		d := xml.NewDecoder(pdmlOut)
		packets := make([]*PdmlPacket, 0, 1000)
		issuedKill := false
	Loop:
		for {
			tok, err := d.Token()
			if err != nil {
				if unexpectedError(err) {
					err = fmt.Errorf("Could not read PDML data: %v", err)
					handleError(err, cb)
				}
				break
			}
			switch tok := tok.(type) {
			case xml.StartElement:
				switch tok.Name.Local {
				case "packet":
					var packet PdmlPacket
					err := d.DecodeElement(&packet, &tok)
					if err != nil {
						if !issuedKill && unexpectedError(err) {
							err = fmt.Errorf("Could not decode PDML data: %v", err)
							handleError(err, cb)
						}
						break Loop
					}
					packets = append(packets, &packet)
					c.updateCacheEntryWithPdml(row, packets, false)
					//if len(pdml2) == 1000 {
					if len(packets) == c.KillAfterReadingThisMany {
						// Shortcut - we never take more than 1000 - so just kill here
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
			if c.highestCachedRow != -1 {
				// try not to evict "end"
				c.PacketCache.Get(c.highestCachedRow)
			}

			c.updateCacheEntryWithPdml(row, packets, !c.ReadingFromFifo())
			if row > c.highestCachedRow {
				c.highestCachedRow = row
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

		c.PcapCmd = c.cmds.Pcap(c.PcapPcap, displayFilterStr)

		pcapOut, err := c.PcapCmd.StdoutPipe()
		if err != nil {
			handleError(err, cb)
			return
		}

		log.Infof("Starting pcap command: %v", c.PcapCmd)

		err = c.PcapCmd.Start()
		if err != nil {
			// e.g. on the pi
			err = fmt.Errorf("Error starting PCAP process %v: %v", c.PcapCmd, err)
			handleError(err, cb)
			return
		}

		defer func() {
			c.PcapCmd.Wait()
		}()

		packets := make([][]byte, 0, 1000)

		globalHdr := [24]byte{}
		pktHdr := [16]byte{}

		_, err = io.ReadFull(pcapOut, globalHdr[:])
		if err != nil {
			if unexpectedError(err) {
				err = fmt.Errorf("Could not read PCAP header: %v", err)
				handleError(err, cb)
			}
			return
		}

		issuedKill := false

		for {
			_, err = io.ReadFull(pcapOut, pktHdr[:])
			if err != nil {
				if unexpectedError(err) {
					err = fmt.Errorf("Could not read PCAP packet header: %v", err)
					handleError(err, cb)
				}
				break
			}

			var value uint32
			value |= uint32(pktHdr[8])
			value |= uint32(pktHdr[9]) << 8
			value |= uint32(pktHdr[10]) << 16
			value |= uint32(pktHdr[11]) << 24

			packet := make([]byte, int(value))
			_, err = io.ReadFull(pcapOut, packet)
			if err != nil {
				if !issuedKill && unexpectedError(err) {
					err = fmt.Errorf("Could not read PCAP packet: %v", err)
					handleError(err, cb)
				}
				break
			}
			packets = append(packets, packet)
			readEnough := (len(packets) >= c.KillAfterReadingThisMany)
			c.updateCacheEntryWithPcap(row, packets, false)

			if readEnough {
				// Shortcut - we never take more than 1000 - so just kill here
				issuedKill = true
				err = termshark.KillIfPossible(c.PcapCmd)
				if err != nil {
					log.Infof("Did not kill pdml process: %v", err)
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
	// Goroutine to track an external shutdown - kills processes i case the external
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

func (c *Loader) turnOffPipe() {
	// Switch over to  the temp pcap file. If a new filter is applied
	// after stopping, we should read from the temp file and not the fifo
	// because nothing will be feeding the fifo.
	c.PcapPsml = c.PcapPdml
}

func (c *Loader) signalPsmlStarting(cb interface{}) {
	handleBegin(cb)
}

func (c *Loader) signalPsmlDone(cb interface{}) {
	ch := c.PsmlFinishedChan
	c.PsmlFinishedChan = make(chan struct{})
	if ae, ok := cb.(IAfterEnd); ok {
		ae.AfterEnd(ch)
		<-ch // wait for the channel to close, which AfterEnd should do
	}
}

func (c *Loader) loadPsmlAsync(cb interface{}) {
	// Used to cancel the tickers below which update list widgets with the latest data and
	// update the progress meter. Note that if ctx is cancelled, then this context is cancelled
	// too. When the 2/3 data loading processes are done, a goroutine will then run uiCtxCancel()
	// to stop the UI updates.

	c.psmlCtx, c.psmlCancelFn = context.WithCancel(c.mainCtx)

	intPsmlCtx, intPsmlCancelFn := context.WithCancel(context.Background())

	// signalling psml done to the goroutine that started

	//======================================================================

	// Make sure data is cleared before we signal we're starting. This gives callbacks a clean
	// view, not the old view of a loader with old data.
	c.Lock()
	c.PacketPsmlData = make([][]string, 0)
	c.PacketPsmlHeaders = make([]string, 0, 10)
	c.Unlock()

	c.PacketCache.Purge()
	c.LoadWasCancelled = false
	c.StartStage2Chan = make(chan struct{}) // do this before signalling start

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

	if c.ReadingFromFifo() {
		// PcapPsml will be nil if here
		pr, pw, err = os.Pipe()
		if err != nil {
			err = fmt.Errorf("Could not create pipe: %v", err)
			handleError(err, cb)
			intPsmlCancelFn()
			return
		}
		// pw is used as Stdout for the tail command, which unwinds in this
		// goroutine - so we can close at this point in the unwinding. pr
		// is used as stdin for the psml command, which also runs in this
		// goroutine.
		defer func() {
			pw.Close()
			pr.Close()
		}()
		c.PcapPsml = pr
	}

	c.Lock()
	c.PsmlCmd = c.cmds.Psml(c.PcapPsml, c.displayFilter)
	c.Unlock()

	psmlOut, err = c.PsmlCmd.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("Could not access pipe output: %v", err)
		handleError(err, cb)
		intPsmlCancelFn()
		return
	}

	log.Infof("Starting PSML command: %v", c.PsmlCmd)

	err = c.PsmlCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting PSML command %v: %v", c.PsmlCmd, err)
		handleError(err, cb)
		intPsmlCancelFn()
		return
	}

	defer func() {
		c.PsmlCmd.Wait()
	}()

	//======================================================================

	// If it was cancelled, then we don't need to start the tail process because
	// psml will read from the tmp pcap file generated by the interface reading
	// process.

	c.tailCmd = nil

	if c.ReadingFromFifo() {
		c.tailCmd = c.cmds.Tail(c.ifaceFile)
		c.tailCmd.SetStdout(pw)

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			err = fmt.Errorf("Could not create FS watch: %v", err)
			handleError(err, cb)
			intPsmlCancelFn()
			return
		}
		defer watcher.Close()

		if err := watcher.Add(c.ifaceFile); err != nil { //&& !os.IsNotExist(err) {
			err = fmt.Errorf("Could not set up watcher for %s: %v", c.ifaceFile, err)
			handleError(err, cb)
			intPsmlCancelFn()
			return
		} else {
			// If it's there, touch it so watcher below is notified that everything is in order
			if _, err := os.Stat(c.ifaceFile); err == nil {
				if err = os.Chtimes(c.ifaceFile, time.Now(), time.Now()); err != nil {
					handleError(err, cb)
					intPsmlCancelFn()
					return
				}
			}

		}

		defer func() {
			watcher.Remove(c.ifaceFile)
		}()

	Loop:
		for {
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()

			select {
			case <-watcher.Events:
				break Loop
			case err := <-watcher.Errors:
				err = fmt.Errorf("Unexpected watcher error for %s: %v", c.ifaceFile, err)
				handleError(err, cb)
				intPsmlCancelFn()
				return
			case <-timer.C:
				err = fmt.Errorf("Giving up waiting for %s: %v", c.ifaceFile, err)
				handleError(err, cb)
				intPsmlCancelFn()
				return
			}
		}

		err = c.tailCmd.Start()
		if err != nil {
			err = fmt.Errorf("Could not start tail command %v: %v", c.tailCmd, err)
			handleError(err, cb)
			intPsmlCancelFn()
			return
		}

		// Do this in a goroutine - in a defer, it would block here before the code executes
		defer func() {
			c.tailCmd.Wait() // this will block the exit of this function until the command is killed
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
				handleError(err, cb)
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
					if line, err := strconv.Unquote("\"" + string(tok) + "\""); err == nil {
						curPsml = append(curPsml, line)
					} else {
						curPsml = append(curPsml, string(tok))
					}
					empty = false
				}
			}
		}
	}
}

func (c *Loader) loadIfaceAsync(cb interface{}) {
	c.ifaceCtx, c.ifaceCancelFn = context.WithCancel(c.mainCtx)

	defer func() {
		ch := c.IfaceFinishedChan
		c.IfaceFinishedChan = make(chan struct{})
		close(ch)
	}()

	c.ifaceCmd = c.cmds.Iface(c.iface, c.captureFilter, c.ifaceFile)

	err := c.ifaceCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting interface reader %v: %v", c.ifaceCmd, err)
		handleError(err, cb)
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

	c.ifaceCmd.Wait() // it definitely started, so we must wait
	// If something killed it, then start the internal shutdown procedure anyway to clean up
	// goroutines waiting on the context.
	c.ifaceCancelFn()
}

//======================================================================

type PdmlPacket struct {
	XMLName xml.Name `xml:"packet"`
	Content []byte   `xml:",innerxml"`
}

type CacheEntry struct {
	Pdml         []*PdmlPacket
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
// Local Variables:
// mode: Go
// fill-column: 78
// End:
