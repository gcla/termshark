// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

// +build tshark

package pcap

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gcla/termshark/v2"

	"github.com/stretchr/testify/assert"
)

//======================================================================

var ensureGoroutinesStopWG2 sync.WaitGroup

func init() {
	Goroutinewg = &ensureGoroutinesStopWG2
}

//======================================================================

// Test using same commands that termshark uses - load 1.pcap. Also tests re-use of a loader.
func TestRealProcs(t *testing.T) {
	loader := NewPcapLoader(Commands{})
	// Make sure we can re-use the same loader, because that's what termshark does
	for _, _ = range []int{1, 2, 3} {
		assert.NotEqual(t, nil, loader)

		// Save now because when psml load finishes, a new one is created
		psmlFinChan := loader.PsmlFinishedChan
		pdmlFinChan := loader.Stage2FinishedChan

		fmt.Printf("about to load real pcap\n")
		updater := struct {
			*pdmlAction
			*waitForEnd
			//*whenIdler
		}{
			newPdmlAction(), newWaitForEnd(),
		}
		loader.doLoadPcapOperation("testdata/1.pcap", "", updater, func() {})

		<-updater.end
		fmt.Printf("done loading real pcap\n")

		assert.Equal(t, 18, len(loader.PacketPsmlData))
		assert.Equal(t, "192.168.86.246", loader.PacketPsmlData[0][2])

		<-psmlFinChan
		assert.Equal(t, LoaderState(LoadingPsml), loader.State())
		loader.SetState(loader.State() & ^LoadingPsml)

		// No pdml yet
		_, ok := loader.PacketCache.Get(0)
		assert.Equal(t, false, ok)

		updater = struct {
			*pdmlAction
			*waitForEnd
		}{
			newPdmlAction(), newWaitForEnd(),
		}
		instructions := []LoadPcapSlice{{0, false}}

		// Won't work yet because state needs to be LoadingPdml - so call again below
		instructionsAfter := ProcessPdmlRequests(instructions, loader, updater)
		assert.Equal(t, LoaderState(LoadingPdml), loader.State())
		assert.Equal(t, 1, len(instructionsAfter)) // not done yet - need to get to right state

		// Load first 1000 rows of pcap as pdml+pcap
		instructionsAfter = ProcessPdmlRequests(instructions, loader, updater)
		<-pdmlFinChan
		assert.Equal(t, LoaderState(LoadingPdml), loader.State())
		loader.SetState(loader.State() & ^LoadingPdml) // manually reset state, termshark handles this
		assert.Equal(t, 0, len(instructionsAfter))

		cei, ok := loader.PacketCache.Get(0)
		assert.Equal(t, true, ok)
		ce := cei.(CacheEntry)
		assert.Equal(t, true, ce.PdmlComplete)
		assert.Equal(t, true, ce.PcapComplete)
		assert.Equal(t, 18, len(ce.Pdml))
		assert.Equal(t, 18, len(ce.Pcap))

		assert.Equal(t, loader.State(), LoaderState(0))

		// Now clear for next run
		fmt.Printf("ABOUT TO CLEAR\n")
		waitForClear := newWaitForClear()
		loader.doClearPcapOperation(waitForClear, func() {})

		assert.Equal(t, loader.State(), LoaderState(0))
		// for _, fn := range waitForClear.idle {
		// 	fn()
		// }
		<-waitForClear.end

		_, ok = loader.PacketCache.Get(0)
		assert.Equal(t, false, ok)

		// So that the next run isn't rejected for being the same
		fmt.Printf("clearing filename state\n")
		loader.pcap = ""
		loader.displayFilter = ""
	}
}

//======================================================================

// an io.Reader that will never hit EOF and will provide data like reading from an interface
type pcapLooper struct {
	io.Reader
}

var _ io.Reader = (*pcapLooper)(nil)

func newPcapLooper(prefix string, suffix string, stopper iStopLoop) *pcapLooper {
	looper := newLoopReader(func() io.ReadCloser {
		file, err := os.Open(fmt.Sprintf("testdata/%s.%s-body", prefix, suffix))
		if err != nil {
			panic(err)
		}
		return file
	}, 100000, stopper)

	fileh, err := os.Open(fmt.Sprintf("testdata/%s.%s-header", prefix, suffix))
	if err != nil {
		panic(err)
	}

	res := &pcapLooper{
		Reader: io.MultiReader(fileh, looper),
	}

	return res
}

//======================================================================

var hdr []byte = []byte{
	0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
}

var pkt []byte = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x39, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00,
	//
	0x30, 0xfd, 0x38, 0xd2, 0x76, 0x12, 0xe8, 0xde,
	0x27, 0x19, 0xde, 0x6c, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2b, 0x93, 0x80, 0x40, 0x00, 0x40, 0x11,
	0xdc, 0x5d, 0xc0, 0xa8, 0x56, 0xf6, 0x45, 0xae,
	0x00, 0x00,
	0xb6, 0x87,
	0x22, 0x61, 0x00, 0x17,
	0xb0, 0xd4, 0x05, 0x0a, 0x06, 0xae, 0x1a, 0xae,
	0x1a, 0xae, 0x1a, 0xae, 0x1a, 0xae, 0x1a, 0xae,
	0x1a,
}

type portfn func() int

type hackedPacket struct {
	idx      int
	port     portfn
	actual   io.Reader
	stopper  iStopLoop
	foocount int
}

var _ io.Reader = (*hackedPacket)(nil)

func (r *hackedPacket) Read(p []byte) (int, error) {
	if r.actual == nil {
		if r.stopper != nil {
			err := r.stopper.shouldStop()
			if err != nil {
				return 0, err
			}
		}

		data := []byte(pkt)
		p := r.port()
		data[r.idx+1] = byte(p & 0xff)
		data[r.idx+0] = byte((p & 0xff00) >> 8)
		//r.actual = strings.NewReader(string(data))
		r.actual = bytes.NewReader(data)
	}
	resi, rese := r.actual.Read(p)
	return resi, rese
}

func newPortLooper(pfn portfn, stopper iStopLoop) io.Reader {
	readers := make([]io.Reader, 65536)
	for i := 0; i < len(readers); i++ {
		readers[i] = &hackedPacket{idx: 34 + 16, port: pfn, stopper: stopper, foocount: i}
	}
	readers = append([]io.Reader{strings.NewReader(string(hdr))}, readers...)
	return io.MultiReader(readers...)
}

//======================================================================

type fakeIfaceCmd struct {
	*simpleCmd
	output io.Writer
	input  io.Reader
}

func newLoopingIfaceCmd(prefix string, stopper iStopLoop) *fakeIfaceCmd {
	return &fakeIfaceCmd{
		simpleCmd: newSimpleCmd(strings.NewReader("")),
		input:     newPcapLooper(prefix, "pcap", stopper), // loop forever until stopper signals to end
	}
}

func newHackedIfaceCmd(pfn portfn, stopper iStopLoop) *fakeIfaceCmd {
	return &fakeIfaceCmd{
		simpleCmd: newSimpleCmd(strings.NewReader("")),
		input:     newPortLooper(pfn, stopper), // loop forever until stopper signals to end
	}
}

func (f *fakeIfaceCmd) Start() error {
	err := f.simpleCmd.Start()
	if err != nil {
		return err
	}
	termshark.TrackedGo(func() {
		n, err := io.Copy(f.output, f.input)
		if err != nil {
			//panic(err)
			//log.Infof("GCLA: err is %T", err)
		}
	}, Goroutinewg)
	return nil
}

func (f *fakeIfaceCmd) Kill() error {
	return f.simpleCmd.Kill()
}

func (f *fakeIfaceCmd) Signal(s os.Signal) error {
	return f.Kill()
}

func (f *fakeIfaceCmd) StdoutPipe() (io.ReadCloser, error) {
	panic(nil)
}

func (f *fakeIfaceCmd) Stdout() io.Writer {
	return f.output
}

func (f *fakeIfaceCmd) SetStdout(w io.WriteCloser) {
	f.output = w
}

//======================================================================

type fakeIface struct {
	prefix  string
	stopper iStopLoop
}

func (f *fakeIface) Iface(iface string, filter string, tmpfile string) IBasicCommand {
	return newLoopingIfaceCmd(f.prefix, f.stopper)
}

//======================================================================

type hackedIface struct {
	stopper iStopLoop
	pfn     portfn
}

func (f *hackedIface) Iface(iface string, filter string, tmpfile string) IBasicCommand {
	return newHackedIfaceCmd(f.pfn, f.stopper)
}

//======================================================================

type IIface interface {
	Iface(iface string, filter string, tmpfile string) IBasicCommand
}

type fakeIfaceCommands struct {
	fake IIface
	Commands
}

var _ ILoaderCmds = fakeIfaceCommands{}

func (c fakeIfaceCommands) Iface(iface string, captureFilter string, tmpfile string) IBasicCommand {
	return c.fake.Iface(iface, captureFilter, tmpfile)
}

//======================================================================

type inputStoppedError struct{}

func (e inputStoppedError) Error() string {
	return "Test stopped input"
}

type chanerr struct {
	err   error
	valid bool
}

type chanfn func() <-chan chanerr

type waitForAnswer struct {
	ch chanfn
}

var _ iStopLoop = (*waitForAnswer)(nil)

func (s *waitForAnswer) shouldStop() error {
	errv := <-s.ch()
	if errv.valid {
		return errv.err
	} else {
		return inputStoppedError{}
	}
}

//======================================================================

func TestIface1(t *testing.T) {
	answerChan := make(chan chanerr)
	getChan := func() <-chan chanerr {
		return answerChan
	}

	fakeIfaceCmd := &fakeIface{
		prefix: "2",
		stopper: &waitForAnswer{
			ch: getChan,
		},
	}
	loader := NewPcapLoader(fakeIfaceCommands{
		fake: fakeIfaceCmd,
	})

	// Save now because when psml load finishes, a new one is created
	psmlFinChan := loader.PsmlFinishedChan
	//ifaceFinChan := loader.IfaceFinishedChan

	updater := newWaitForEnd()
	ch := make(chan struct{})

	// Start the packet generation and reading process
	loader.doLoadInterfaceOperation("dummy", "", "", updater, func() { close(ch) })
	<-ch

	fmt.Printf("fake sleep\n")
	time.Sleep(1 * time.Second)

	read := 10000
	fmt.Printf("reading %d packets from looper\n", read)
	for i := 0; i < read-1; i++ { // otherwise it reads one too many
		answerChan <- chanerr{err: nil, valid: true}
	}

	fmt.Printf("giving processes time to catch up\n")
	time.Sleep(2 * time.Second)

	fmt.Printf("stopping iface read\n")
	ch = make(chan struct{})
	updater = newWaitForEnd()

	// Stop the packet generation and reading process
	loader.doStopLoadOperation(updater, func() {
		close(ch)
	})
	close(answerChan)
	fmt.Printf("waiting for loader to signal end\n")
	<-psmlFinChan

	fmt.Printf("done loading interface pcap\n")

	assert.NotEqual(t, 0, len(loader.PacketPsmlData))
	assert.Equal(t, read, len(loader.PacketPsmlData))
	assert.Equal(t, "192.168.44.123", loader.PacketPsmlData[0][2])

	assert.Equal(t, LoaderState(LoadingPsml|LoadingIface), loader.State())
	loader.SetState(loader.State() & ^(LoadingPsml | LoadingIface))

	// After SetState call, state should be idle, meaning my channel will be closed at last
	<-ch
	fmt.Printf("waiting for updater end to signal end\n")
	<-updater.end

	// Now clear for next run
	fmt.Printf("about to clear\n")
	waitForClear := newWaitForClear()
	ch = make(chan struct{})
	loader.doClearPcapOperation(waitForClear, func() { close(ch) })
	<-ch

	assert.Equal(t, loader.State(), LoaderState(0))
	// for _, fn := range waitForClear.idle {
	// 	fn()
	// }
	<-waitForClear.end

	assert.Equal(t, 0, len(loader.PacketPsmlData))

	// So that the next run isn't rejected for being the same
	fmt.Printf("clearing filename state\n")
	loader.pcap = ""
	loader.displayFilter = ""
}

func TestIfaceNewFilter(t *testing.T) {
	port := 0

	pfn := func() int {
		res := port
		port++
		return res
	}

	answerChan := make(chan chanerr)
	getChan := func() <-chan chanerr {
		return answerChan
	}

	hackedIfaceCmd := &hackedIface{
		stopper: &waitForAnswer{
			ch: getChan,
		},
		pfn: pfn,
	}
	cmds := fakeIfaceCommands{
		fake: hackedIfaceCmd,
	}
	loader := NewPcapLoader(cmds)

	// Save now because when psml load finishes, a new one is created
	psmlFinChan := loader.PsmlFinishedChan

	filtcount := 1000
	updater := newWaitForEnd()
	fmt.Printf("buggy foo doing load interface op\n")
	ch := make(chan struct{})
	loader.doLoadInterfaceOperation("dummy", "", fmt.Sprintf("frame.number <= %d", filtcount), updater, func() { close(ch) })
	<-ch

	fmt.Printf("fake sleep\n")
	time.Sleep(1 * time.Second)

	read := 30000
	fmt.Printf("fake reading %d packets from looper\n", read)
	for i := 0; i < read; i++ {
		//fmt.Printf("loop 1: sending answerchan for %d\n", i)
		answerChan <- chanerr{err: nil, valid: true}
		//fmt.Printf("loop 1: sending answerchan for %d\n", i)
	}

	fmt.Printf("fake giving processes time to catch up\n")
	time.Sleep(2 * time.Second)

	fmt.Printf("fake stopping iface read\n")
	ch = make(chan struct{})
	loader.doStopLoadToIfaceOperation(func() { close(ch) })
	close(answerChan)

	fmt.Printf("fake waiting for loader to signal end\n")
	<-psmlFinChan

	fmt.Printf("fake done loading interface pcap\n")

	fmt.Printf("fake num packets was %d\n", len(loader.PacketPsmlData))
	assert.NotEqual(t, 0, len(loader.PacketPsmlData))
	assert.Equal(t, filtcount, len(loader.PacketPsmlData))
	assert.Equal(t, "192.168.86.246", loader.PacketPsmlData[0][2])

	re, _ := regexp.Compile("^[0-9]+ ")

	// Check the source port is correct for each packet read
	for i := 0; i < filtcount; i++ {
		s := loader.PacketPsmlData[i][6]
		if re.MatchString(s) { // rule out those where tshark converts port to name
			pref := fmt.Sprintf("%d", i)
			res := strings.HasPrefix(s, pref)
			assert.True(t, res)
		}
	}

	assert.Equal(t, LoaderState(LoadingPsml|LoadingIface), loader.State())
	loader.SetState(loader.State() & ^LoadingPsml)

	// Now SetState called, can get these channel results
	fmt.Printf("fake waiting for updater end to signal end\n")
	<-updater.end
	<-ch

	// Now reload with new filter

	// Save now because when psml load finishes, a new one is created
	psmlFinChan = loader.PsmlFinishedChan

	answerChan = make(chan chanerr)
	filtcount = 1000
	port = 0
	updater = newWaitForEnd()

	fmt.Printf("buggy foo fake doing load interface op\n")
	ch = make(chan struct{})
	loader.doLoadInterfaceOperation("dummy", "", fmt.Sprintf("frame.number > 500 && frame.number <= %d", filtcount+500), updater, func() { close(ch) })
	<-ch
	//loader.doLoadInterfaceOperation("dummy", fmt.Sprintf("frame.number <= %d", filtcount+1), gwtest.D, updater)

	fmt.Printf("fake sleep 22\n")
	time.Sleep(1 * time.Second)

	// The iface reader doesn't need to read more packets - we are only applying a new filter

	fmt.Printf("loop 2: fake giving processes time to catch up\n")
	time.Sleep(2 * time.Second)

	fmt.Printf("loop 2: fake stopping iface read\n")
	ich := loader.IfaceFinishedChan // save the channel here, because it is reassigned before closing
	updater = newWaitForEnd()
	ch = make(chan struct{})
	loader.doStopLoadOperation(updater, func() { close(ch) })
	// in case the read is blocked here
	close(answerChan)

	fmt.Printf("loop 2: fake waiting for loader to signal end\n")
	<-psmlFinChan

	fmt.Printf("fake num packets was %d\n", len(loader.PacketPsmlData))
	assert.NotEqual(t, 0, len(loader.PacketPsmlData))
	assert.Equal(t, filtcount, len(loader.PacketPsmlData))
	// assert.Equal(t, "192.168.86.246", loader.PacketPsmlData[0][2])

	// Check the source port is correct for each packet read
	for i := 0; i < filtcount; i++ {
		s := loader.PacketPsmlData[i][6]
		if re.MatchString(s) { // rule out those where tshark converts port to name
			pref := fmt.Sprintf("%d", i+500)
			res := strings.HasPrefix(s, pref)
			assert.True(t, res)
		}
	}

	// stop iface
	fmt.Printf("fake waiting for iface to stop\n")
	//loader.stopLoadIface()
	<-ich
	fmt.Printf("fake iface stopped\n")

	assert.Equal(t, LoaderState(LoadingPsml|LoadingIface), loader.State())
	loader.SetState(0)

	<-ch
	fmt.Printf("loop 2: waiting for updater end to signal end\n")
	<-updater.end
	fmt.Printf("loop 2: done loading interface pcap\n")

	// Now clear and test
	fmt.Printf("loop 2: about to clear\n")
	waitForClear := newWaitForClear()
	ch = make(chan struct{})
	loader.doClearPcapOperation(waitForClear, func() { close(ch) })
	<-ch

	assert.Equal(t, loader.State(), LoaderState(0))
	<-waitForClear.end

	assert.Equal(t, 0, len(loader.PacketPsmlData))
}

//======================================================================

func TestKeepThisLast2(t *testing.T) {
	TestKeepThisLast(t)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
