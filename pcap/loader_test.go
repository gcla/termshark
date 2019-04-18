// Copyright 2019 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package pcap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"net/http"
	_ "net/http"
	_ "net/http/pprof"

	"github.com/gcla/termshark"
	"github.com/stretchr/testify/assert"

	log "github.com/sirupsen/logrus"
)

//======================================================================

var ensureGoroutinesStopWG sync.WaitGroup

func init() {
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()

	Goroutinewg = &ensureGoroutinesStopWG
}

//======================================================================

type pdmlAction struct{}

func newPdmlAction() *pdmlAction {
	return &pdmlAction{}
}

func (p *pdmlAction) WhenLoadingPdml() {
	fmt.Printf("FURTHER ACTION: when loading pdml\n")
}
func (p *pdmlAction) WhenNotLoadingPdml() {
	fmt.Printf("FURTHER ACTION: when not loading pdml\n")
}

//======================================================================

type iGoProc interface {
	StopGR()
}

type procReader struct {
	io.ReadCloser
	iGoProc
}

var _ io.Reader = (*procReader)(nil)

func (r *procReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	//fmt.Printf("Read result %d, %v\n", n, err)
	if err != nil {
		r.StopGR()
	}
	return n, err
}

//======================================================================

type iStopLoop interface {
	shouldStop() error
}

type bodyMakerFn func() io.ReadCloser

type loopReader struct {
	maker   bodyMakerFn
	loops   int
	stopper iStopLoop
	body    io.ReadCloser
	numdone int
}

var _ io.Reader = (*loopReader)(nil)

func newLoopReader(maker bodyMakerFn, loops int, stopper iStopLoop) *loopReader {
	res := &loopReader{
		maker:   maker,
		loops:   loops,
		stopper: stopper,
	}
	res.body = maker()
	return res
}

func (r *loopReader) Read(p []byte) (int, error) {
	read := 0
	for read < len(p) {
		if r.numdone == r.loops {
			return read, io.EOF
		}
		req := len(p[read:])
		n, err := r.body.Read(p[read:])
		read += n
		if err != nil {
			if err != io.EOF {
				return read, err
			}
			r.numdone += 1 // EOF
			r.body.Close()
			r.body = r.maker()
			if r.stopper != nil {
				err = r.stopper.shouldStop()
				if err != nil {
					return read, err
				}
			}
		} else if n < req {
			break
		}
	}

	return read, nil
}

//======================================================================

// Implements io.Reader - combines header, looping body and footer from disk
type pcapLoopReader struct {
	io.Reader
	loops int
}

var _ io.Reader = (*pcapLoopReader)(nil)

func newPcapLoopReader(prefix string, suffix string, loops int, stopper iStopLoop) *pcapLoopReader {
	looper := newLoopReader(func() io.ReadCloser {
		file, err := os.Open(fmt.Sprintf("testdata/%s.%s-body", prefix, suffix))
		if err != nil {
			panic(err)
		}
		return file
	}, loops, stopper)

	fileh, err := os.Open(fmt.Sprintf("testdata/%s.%s-header", prefix, suffix))
	if err != nil {
		panic(err)
	}
	filef, err := os.Open(fmt.Sprintf("testdata/%s.%s-footer", prefix, suffix))
	if err != nil {
		panic(err)
	}

	res := &pcapLoopReader{
		Reader: io.MultiReader(fileh, looper, filef),
		loops:  loops,
	}

	return res
}

//======================================================================

// Provide Tail, Pdml, etc based on files on disk
type procsFromPrefix struct {
	prefix string
}

var _ ILoaderCmds = procsFromPrefix{}

func makeProcsFromPrefix(pref string) procsFromPrefix {
	return procsFromPrefix{prefix: pref}
}

func (g procsFromPrefix) Iface(iface string, captureFilter string, tmpfile string) IBasicCommand {
	panic(fmt.Errorf("Should not need"))
}

func (g procsFromPrefix) Tail(tmpfile string) ITailCommand {
	panic(fmt.Errorf("Should not need"))
}

func (g procsFromPrefix) Psml(pcap interface{}, filter string) IPcapCommand {
	file, err := os.Open(fmt.Sprintf("testdata/%s.psml", g.prefix))
	if err != nil {
		panic(err)
	}
	return newSimpleCmd(file)
}

func (g procsFromPrefix) Pcap(pcap string, filter string) IPcapCommand {
	file, err := os.Open(fmt.Sprintf("testdata/%s.pcap", g.prefix))
	if err != nil {
		panic(err)
	}
	return newSimpleCmd(file)
}

func (g procsFromPrefix) Pdml(pcap string, filter string) IPcapCommand {
	file, err := os.Open(fmt.Sprintf("testdata/%s.pdml", g.prefix))
	if err != nil {
		panic(err)
	}
	return newSimpleCmd(file)
}

//======================================================================

type loopingProcs struct {
	prefix string
	loops  int
}

var _ ILoaderCmds = loopingProcs{}

func makeLoopingProcs(pref string, loops int) loopingProcs {
	return loopingProcs{prefix: pref, loops: loops}
}

func (g loopingProcs) Iface(iface string, captureFilter string, tmpfile string) IBasicCommand {
	panic(fmt.Errorf("Should not need"))
}

func (g loopingProcs) Tail(tmpfile string) ITailCommand {
	panic(fmt.Errorf("Should not need"))
}

func (g loopingProcs) Psml(pcap interface{}, filter string) IPcapCommand {
	rd := newPcapLoopReader(g.prefix, "psml", g.loops, nil)
	return newSimpleCmd(rd)
}

func (g loopingProcs) Pcap(pcap string, filter string) IPcapCommand {
	rd := newPcapLoopReader(g.prefix, "pcap", g.loops, nil)
	return newSimpleCmd(rd)
}

func (g loopingProcs) Pdml(pcap string, filter string) IPcapCommand {
	rd := newPcapLoopReader(g.prefix, "pdml", g.loops, nil)
	return newSimpleCmd(rd)
}

//======================================================================

// A pretend external command - when started, runs a goroutine that waits until stopped
type simpleCmd struct {
	pcap    string
	filter  string
	out     io.Writer
	pipe    io.ReadCloser
	started bool
	dead    bool
	ctx     context.Context // cancels the iface reader process
	cancel  context.CancelFunc
}

var _ ICommand = (*simpleCmd)(nil)

func newSimpleCmd(rd io.Reader) *simpleCmd {
	res := &simpleCmd{}

	var rc io.ReadCloser
	var ok bool
	rc, ok = rd.(io.ReadCloser)
	if !ok {
		rc = ioutil.NopCloser(rd)
	}

	res.pipe = &procReader{
		ReadCloser: rc,
		iGoProc:    res,
	}

	return res
}

func (f *simpleCmd) StopGR() {
	f.cancel()
}

func (f *simpleCmd) Start() error {
	if f.started {
		return fmt.Errorf("Started already")
	}
	if f.dead {
		return fmt.Errorf("Started already and dead")
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	termshark.TrackedGo(func() {
		select {
		case <-f.ctx.Done(): // terminate
		}
	}, Goroutinewg)
	f.started = true
	return nil
}

func (f *simpleCmd) Wait() error {
	if !f.started {
		return fmt.Errorf("Not started yet")
	}
	if f.dead {
		return fmt.Errorf("Dead already")
	}
	select {
	case <-f.ctx.Done():
		f.dead = true
	}
	return nil
}

func (f *simpleCmd) StdoutPipe() (io.ReadCloser, error) {
	return f.pipe, nil
}

func (f *simpleCmd) SetStdout(w io.Writer) {
	f.out = w
}

func (f *simpleCmd) Kill() error {
	f.cancel()
	return nil
}

func (f *simpleCmd) Signal(s os.Signal) error {
	f.cancel()
	return nil
}

func (f *simpleCmd) Pid() int {
	return 1001
}

//======================================================================

// While tshark processes are running, signal (via close) when AfterEnd is triggered
type waitForEnd struct {
	end chan struct{}
}

var _ IOnError = (*waitForEnd)(nil)
var _ IClear = (*waitForEnd)(nil)
var _ IBeforeBegin = (*waitForEnd)(nil)
var _ IAfterEnd = (*waitForEnd)(nil)

func newWaitForEnd() *waitForEnd {
	return &waitForEnd{
		end: make(chan struct{}),
	}
}

func (p *waitForEnd) BeforeBegin(closeMe chan<- struct{}) {
	close(closeMe)
}
func (p *waitForEnd) AfterEnd(closeMe chan<- struct{}) {
	close(closeMe)
	close(p.end)
}
func (p *waitForEnd) OnClear(closeMe chan<- struct{}) {
	close(closeMe)
}
func (p *waitForEnd) OnError(err error, closeMe chan<- struct{}) {
	close(closeMe)
	panic(err)
}

//======================================================================

type waitForClear struct {
	end chan struct{}
}

var _ IOnError = (*waitForClear)(nil)
var _ IClear = (*waitForClear)(nil)
var _ IBeforeBegin = (*waitForClear)(nil)
var _ IAfterEnd = (*waitForClear)(nil)

func newWaitForClear() *waitForClear {
	return &waitForClear{
		end: make(chan struct{}),
	}
}

func (p *waitForClear) BeforeBegin(closeMe chan<- struct{}) {
	close(closeMe)
}
func (p *waitForClear) AfterEnd(closeMe chan<- struct{}) {
	close(closeMe)
}
func (p *waitForClear) OnClear(closeMe chan<- struct{}) {
	close(p.end)
	close(closeMe)
}
func (p *waitForClear) OnError(err error, closeMe chan<- struct{}) {
	close(closeMe)
	panic(err)
}

//======================================================================

type enabler struct {
	val *bool
}

func (e enabler) EnableOperations() {
	*e.val = true
}

//======================================================================

func TestSimpleCmd(t *testing.T) {
	p := newSimpleCmd(bytes.NewReader([]byte("hello world")))

	err := p.Start()
	assert.NoError(t, err)

	so, err := p.StdoutPipe()
	assert.NoError(t, err)

	read, err := ioutil.ReadAll(so)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(read))

	err = p.Wait()
	assert.NoError(t, err)
}

func TestLoopReader1(t *testing.T) {
	maker := func() io.ReadCloser {
		return ioutil.NopCloser(strings.NewReader("hello"))
	}

	looper := newLoopReader(maker, 3, nil)

	read, err := ioutil.ReadAll(looper)
	assert.NoError(t, err)
	assert.Equal(t, "hellohellohello", string(read))

	looper = newLoopReader(maker, 3, nil)
	ball := make([]byte, 0)
	b1 := make([]byte, 1)
	var n int

	err = nil
	for err != io.EOF {
		n, err = looper.Read(b1)
		if err != io.EOF {
			assert.Equal(t, 1, n)
			ball = append(ball, b1...)
		}
	}

	assert.Equal(t, "hellohellohello", string(ball))
}

//======================================================================

// Load psml+pdml+pcap from testdata/1.pcap, validate the data
func TestSinglePcap(t *testing.T) {
	loader := NewPcapLoader(makeProcsFromPrefix("1"))
	assert.NotEqual(t, nil, loader)

	// Save now because when psml load finishes, a new one is created
	psmlFinChan := loader.PsmlFinishedChan
	pdmlFinChan := loader.Stage2FinishedChan

	enabled := false

	updater := struct {
		*pdmlAction
		*waitForEnd
		enabler
	}{
		newPdmlAction(), newWaitForEnd(), enabler{&enabled},
	}
	done := make(chan struct{}, 1)
	loader.doLoadPcapOperation("abc", "def", updater, func() {
		close(done)
	})
	<-updater.end
	<-done

	assert.Equal(t, 18, len(loader.PacketPsmlData))
	assert.Equal(t, "192.168.86.246", loader.PacketPsmlData[0][2])

	<-psmlFinChan
	assert.Equal(t, LoaderState(LoadingPsml), loader.State())
	loader.SetState(loader.State() & ^LoadingPsml)

	// No pdml yet
	_, ok := loader.PacketCache.Get(0)
	assert.Equal(t, false, ok)

	//further := pdmlAction{}
	enabled = false
	updater = struct {
		*pdmlAction
		*waitForEnd
		enabler
	}{
		newPdmlAction(), newWaitForEnd(), enabler{&enabled},
	}
	instructions := []LoadPcapSlice{{0, false}}

	instructionsAfter := ProcessPdmlRequests(instructions, loader, updater)
	assert.Equal(t, LoaderState(LoadingPdml), loader.State())
	assert.Equal(t, 1, len(instructionsAfter)) // not done yet - need to get to right state

	instructionsAfter = ProcessPdmlRequests(instructions, loader, updater)
	<-pdmlFinChan
	assert.Equal(t, LoaderState(LoadingPdml), loader.State())
	loader.SetState(loader.State() & ^LoadingPdml)
	assert.Equal(t, 0, len(instructionsAfter))

	cei, ok := loader.PacketCache.Get(0)
	assert.Equal(t, true, ok)
	ce := cei.(CacheEntry)
	assert.Equal(t, true, ce.PdmlComplete)
	assert.Equal(t, true, ce.PcapComplete)
	assert.Equal(t, 18, len(ce.Pdml))
	assert.Equal(t, 18, len(ce.Pcap))
}

func TestLoopingPcap(t *testing.T) {
	for i, loops := range []int{1, 5, 100} {
		// The "2" loads up testdata/2.{psml,pdml,pcap}-{header,body,footer}
		loader := NewPcapLoader(makeLoopingProcs("2", loops))
		// Make sure we can re-use the same loader, because that's what termshark does
		for j, _ := range []int{1, 2} {
			assert.NotEqual(t, nil, loader)

			// Save now because when psml load finishes, a new one is created
			psmlFinChan := loader.PsmlFinishedChan
			pdmlFinChan := loader.Stage2FinishedChan

			// make sure each time round it tries to load a "new" pcap - otherwise the loader
			// returns early, and this test is set up to wait until we get the AfterEnd signal
			fakePcap := fmt.Sprintf("%d-%d", i, j)

			enabled := false
			updater := struct {
				*pdmlAction
				*waitForEnd
				enabler
			}{
				newPdmlAction(), newWaitForEnd(), enabler{&enabled},
			}
			done := make(chan struct{}, 1)
			loader.doLoadPcapOperation(fakePcap, "def", updater, func() {
				close(done)
			})
			<-updater.end
			<-done

			assert.Equal(t, loops, len(loader.PacketPsmlData))
			assert.Equal(t, "192.168.44.123", loader.PacketPsmlData[0][2])

			<-psmlFinChan
			assert.Equal(t, LoaderState(LoadingPsml), loader.State())
			loader.SetState(loader.State() & ^LoadingPsml)

			// No pdml yet
			_, ok := loader.PacketCache.Get(0)
			assert.Equal(t, false, ok)

			updater = struct {
				*pdmlAction
				*waitForEnd
				enabler
			}{
				newPdmlAction(), newWaitForEnd(), enabler{&enabled},
			}
			instructions := []LoadPcapSlice{{0, false}}

			instructionsAfter := ProcessPdmlRequests(instructions, loader, updater)
			assert.Equal(t, LoaderState(LoadingPdml), loader.State())
			assert.Equal(t, 1, len(instructionsAfter)) // not done yet - need to get to right state

			instructionsAfter = ProcessPdmlRequests(instructions, loader, updater)
			<-pdmlFinChan
			assert.Equal(t, LoaderState(LoadingPdml), loader.State())
			loader.SetState(loader.State() & ^LoadingPdml)
			assert.Equal(t, 0, len(instructionsAfter))

			cei, ok := loader.PacketCache.Get(0)
			assert.Equal(t, true, ok)
			ce := cei.(CacheEntry)
			assert.Equal(t, true, ce.PdmlComplete)
			assert.Equal(t, true, ce.PcapComplete)
			assert.Equal(t, loops, len(ce.Pdml))
			assert.Equal(t, loops, len(ce.Pcap))
			assert.Equal(t, loader.State(), LoaderState(0))

			fmt.Printf("about to clear\n")
			done = make(chan struct{}, 1)
			waitForClear := newWaitForClear()
			loader.doClearPcapOperation(waitForClear, func() {
				close(done)
			})
			<-done

			assert.Equal(t, loader.State(), LoaderState(0))
			<-waitForClear.end

			assert.Equal(t, 0, len(loader.PacketPsmlData))

			_, ok = loader.PacketCache.Get(0)
			assert.Equal(t, false, ok)
		}
	}
}

//======================================================================

func TestKeepThisLast(t *testing.T) {
	fmt.Printf("Waiting for test goroutines to stop\n")
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-time.After(10 * time.Second):
			assert.FailNow(t, "Not all test goroutines terminated in 10s")
		}
	}()
	Goroutinewg.Wait()
	close(done)
	fmt.Printf("Done waiting for test goroutines to stop\n")
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
