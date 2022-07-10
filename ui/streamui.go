// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/pkg/streams"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/streamwidget"
	"github.com/gdamore/tcell/v2"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

var streamViewNoKeysHolder *holder.Widget
var streamView *appkeys.KeyWidget
var conversationMenu *menu.Widget
var conversationMenuHolder *holder.Widget

var streamsPcapSize int64

var currentStreamKey *streamKey
var streamWidgets *lru.Cache // map[streamKey]*streamwidget.Widget

var StreamLoader *streams.Loader // DOC - one because it holds stream index state for pcap

//======================================================================

// The index for the stream widget cache e.g. UDP stream 6
type streamKey struct {
	proto streams.Protocol
	idx   int
}

//======================================================================

type ManageStreamCache struct{}

var _ pcap.INewSource = ManageStreamCache{}
var _ pcap.IClear = ManageStreamCache{}

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageStreamCache) OnNewSource(pcap.HandlerCode, gowid.IApp) {
	clearStreamState()
}

func (t ManageStreamCache) OnClear(pcap.HandlerCode, gowid.IApp) {
	clearStreamState()
}

//======================================================================

func streamKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	if evk.Rune() == 'q' || evk.Rune() == 'Q' || evk.Key() == tcell.KeyEscape {
		closeStreamUi(app, true)
		StreamLoader.StopLoad()
		handled = true
	}
	return handled
}

func startStreamReassembly(app gowid.IApp) {
	var model *pdmltree.Model
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			rid, _ := packetListView.Model().RowIdentifier(fxy.Row)
			row := int(rid)
			model = getCurrentStructModel(row)
		}
	}
	if model == nil {
		OpenError("No packets available.", app)
		return
	}

	proto := streams.TCP
	streamIndex := model.TCPStreamIndex()
	if streamIndex.IsNone() {
		proto = streams.UDP
		streamIndex = model.UDPStreamIndex()
		if streamIndex.IsNone() {
			OpenError("Please select a TCP or UDP packet.", app)
			return
		}
	}

	filterProto := gwutil.If(proto == streams.TCP, "tcp", "udp").(string)

	filter := fmt.Sprintf("%s.stream eq %d", filterProto, streamIndex.Val())

	previousFilterValue := FilterWidget.Value()

	FilterWidget.SetValue(filter, app)
	RequestNewFilter(filter, app)

	currentStreamKey = &streamKey{proto: proto, idx: streamIndex.Val()}

	newSize, reset := termshark.FileSizeDifferentTo(Loader.PcapPdml, streamsPcapSize)
	if reset {
		streamWidgets = nil
	}

	// we maintain an lru.Cache of stream widgets so that we can quickly re-open
	// the UI for streams that have been calculated before.
	if streamWidgets == nil {
		initStreamWidgetCache()
		streamsPcapSize = newSize
	}

	var swid *streamwidget.Widget
	swid2, ok := streamWidgets.Get(*currentStreamKey)

	if ok {
		swid = swid2.(*streamwidget.Widget)
		ok = swid.Finished()
	}

	if ok {
		openStreamUi(swid, app)
	} else {
		swid = makeStreamWidget(previousFilterValue, filter, Loader.String(), proto)
		streamWidgets.Add(*currentStreamKey, swid)

		// Use the source context. At app shutdown, canceling main will cancel src which will cancel the stream
		// loader. And changing source should also cancel the stream loader on all occasions.
		StreamLoader = streams.NewLoader(streams.MakeCommands(), Loader.Context())

		sh := &streamParseHandler{
			app:   app,
			name:  Loader.String(),
			proto: proto,
			idx:   streamIndex.Val(),
			wid:   swid,
		}

		StreamLoader.StartLoad(
			Loader.PcapPdml,
			filterProto,
			streamIndex.Val(),
			app,
			sh,
		)
	}
}

//======================================================================

type streamParseHandler struct {
	app              gowid.IApp
	tick             *time.Ticker // for updating the spinner
	stopChunks       chan struct{}
	stopIndices      chan struct{}
	chunks           chan streams.IChunk
	pktIndices       chan int
	name             string
	proto            streams.Protocol
	idx              int
	wid              *streamwidget.Widget
	pleaseWaitClosed bool
	openedStreams    bool
	sync.Mutex
}

var _ streams.IOnStreamChunk = (*streamParseHandler)(nil)
var _ streams.IOnStreamHeader = (*streamParseHandler)(nil)
var _ pcap.IBeforeBegin = (*streamParseHandler)(nil)
var _ pcap.IAfterEnd = (*streamParseHandler)(nil)
var _ pcap.IOnError = (*streamParseHandler)(nil)

// Run from the app goroutine
func (t *streamParseHandler) drainChunks() int {
	curLen := len(t.chunks)
	for i := 0; i < curLen; i++ {
		chunk := <-t.chunks
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(t.app)
		}

		t.wid.AddChunkEntire(chunk, t.app)
	}
	return curLen
}

// Run from the app goroutine
func (t *streamParseHandler) drainPacketIndices() int {
	curLen := len(t.pktIndices)
	for i := 0; i < curLen; i++ {
		packet := <-t.pktIndices
		t.wid.TrackPayloadPacket(packet)
	}
	return curLen
}

func (t *streamParseHandler) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.StreamCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenPleaseWait(appView, app)
	}))

	t.tick = time.NewTicker(time.Duration(200) * time.Millisecond)
	t.stopChunks = make(chan struct{})
	t.stopIndices = make(chan struct{})
	t.chunks = make(chan streams.IChunk, 1000)
	t.pktIndices = make(chan int, 1000)

	// Start this after widgets have been cleared, to get focus change
	termshark.TrackedGo(func() {
		fn := func() {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				t.drainChunks()

				if !t.openedStreams {
					appViewNoKeys.SetSubWidget(streamView, app)
					openStreamUi(t.wid, app)
					t.openedStreams = true
				}
			}))
		}

		termshark.RunOnDoubleTicker(t.stopChunks, fn,
			time.Duration(200)*time.Millisecond,
			time.Duration(200)*time.Millisecond,
			10)
	}, Goroutinewg)

	termshark.TrackedGo(func() {
		fn := func() {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				t.drainPacketIndices()
			}))
		}

		termshark.RunOnDoubleTicker(t.stopIndices, fn,
			time.Duration(200)*time.Millisecond,
			time.Duration(200)*time.Millisecond,
			10)
	}, Goroutinewg)

	termshark.TrackedGo(func() {
	Loop:
		for {
			select {
			case <-t.tick.C:
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					pleaseWaitSpinner.Update()
				}))
			case <-t.stopChunks:
				break Loop
			}
		}
	}, Goroutinewg)
}

func (t *streamParseHandler) AfterIndexEnd(success bool) {
	t.wid.SetFinished(success)
	close(t.stopIndices)

	for {
		if t.drainPacketIndices() == 0 {
			break
		}
	}
}

func (t *streamParseHandler) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.StreamCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(app)
		}
		if !t.openedStreams {
			openStreamUi(t.wid, app)
			t.openedStreams = true
		}

		// Clear out anything lingering from last ticker run to now
		for {
			if t.drainChunks() == 0 {
				break
			}
		}

		if t.wid.NumChunks() == 0 {
			OpenMessage("No stream payloads found.", appView, app)
		}
	}))
	close(t.stopChunks)
}

func (t *streamParseHandler) TrackPayloadPacket(packet int) {
	t.Lock()
	defer t.Unlock()
	t.pktIndices <- packet
}

func (t *streamParseHandler) OnStreamHeader(hdr streams.FollowHeader) {
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		t.wid.AddHeader(hdr, app)
	}))
}

// Handle a line/chunk of input - one piece of reassembled data, which comes with
// a client/server direction.
func (t *streamParseHandler) OnStreamChunk(chunk streams.IChunk) {
	t.Lock()
	defer t.Unlock()
	t.chunks <- chunk
}

func (t *streamParseHandler) OnError(code pcap.HandlerCode, app gowid.IApp, err error) {
	if code&pcap.StreamCode == 0 {
		return
	}
	log.Error(err)
	if !Running {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		RequestQuit()
	} else if !profiles.ConfBool("main.suppress-tshark-errors", true) {
		var errstr string
		if kverr, ok := err.(gowid.KeyValueError); ok {
			errstr = termshark.KeyValueErrorString(kverr)
		} else {
			errstr = fmt.Sprintf("%v", err)
		}

		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			OpenLongError(errstr, app)
		}))
	}
}

func initStreamWidgetCache() {
	widgetCacheSize := profiles.ConfInt("main.stream-cache-size", 100)

	var err error
	streamWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Initialized stream widget cache with %d entries.", widgetCacheSize)
}

func clearStreamState() {
	initStreamWidgetCache()
	currentStreamKey = nil
}

type streamClicker struct{}

var _ streamwidget.IChunkClicked = streamClicker{}

func (c streamClicker) OnPacketClicked(pkt int, app gowid.IApp) error {
	if packetListView != nil {
		coords, err := packetListView.FocusXY()
		if err == nil {
			// Need to go from row identifier ("9th packet") to display order which might be sorted.
			// Note that for our pcap table, the row identifier (logical id) for each table row is
			// itself an int i.e. packet #0, packet #1 (although the packet's *frame number* might
			// be different if there's a filter). When OnChunkClicked() is called, it means react
			// to a click on the logical packet #N (where the stream loader tracks pcap packet ->
			// packet-with-payload). So
			//
			// - user clicks on 9th item in stream view
			// - the stream loader translates this to the 15th packet in the pcap (rest are SYN, etc)
			// - the inverted table model translates this to display row #5 in the table (because it's sorted)
			// - then we set the display row and switch to the data/away from the table header
			//
			if row, ok := packetListView.InvertedModel().IdentifierToRow(table.RowId(pkt)); !ok {
				OpenError(fmt.Sprintf("Unexpected error looking up packet %v.", pkt), app)
			} else {
				coords.Row = row // cast to int - we want row == #item in list
				packetListView.SetFocusXY(app, coords)
				packetListTable.SetFocusOnData(app)
				packetListTable.GoToMiddle(app)
				setFocusOnPacketList(app)
				packetListData := packetListView.Model().(table.ISimpleDataProvider).GetData()
				// This condition should always be true. I just feel cautious because accessing the psml data
				// in this way feels fragile. Also, take note: there's an open issue to make it possible to
				// customize the packet headers, in which case the item at index 0 in the psml might not be
				// the frame number (though this check doesn't guard against that...). It's more useful
				// to display the actual frame number if possible, so do that if we can, otherwise just
				// display which segment of the stream this is.
				if len(packetListData) > row && len(packetListData[row]) > 0 {
					OpenMessage(fmt.Sprintf("Selected packet %s.", packetListData[row][0]), appView, app)
				} else {
					OpenMessage(fmt.Sprintf("Selected segment %d.", pkt+1), appView, app)
				}
			}
		}
	}

	return nil
}

func (c streamClicker) HandleError(row table.RowId, err error, app gowid.IApp) {
	OpenError(fmt.Sprintf("Packet at row %v is not loaded yet. Try again in a few seconds.", row), app)
}

//======================================================================

type simpleOnError struct{}

func (s simpleOnError) OnError(msg string, app gowid.IApp) {
	OpenError(msg, app)
}

func makeStreamWidget(previousFilter string, filter string, cap string, proto streams.Protocol) *streamwidget.Widget {
	return streamwidget.New(filter, cap, proto,
		conversationMenu, conversationMenuHolder, &keyState,
		streamwidget.Options{
			MenuOpener: &multiMenu1Opener,
			DefaultDisplay: func() streamwidget.DisplayFormat {
				view := streamwidget.Hex
				choice := profiles.ConfString("main.stream-view", "hex")
				switch choice {
				case "raw":
					view = streamwidget.Raw
				case "ascii":
					view = streamwidget.Ascii
				}
				return view
			},
			PreviousFilter: previousFilter,
			FilterOutFunc: func(w streamwidget.IFilterOut, app gowid.IApp) {
				closeStreamUi(app, true)

				var newFilter string
				if w.PreviousFilter() == "" {
					newFilter = fmt.Sprintf("!(%s)", w.DisplayFilter())
				} else {
					newFilter = fmt.Sprintf("%s and !(%s)", w.PreviousFilter(), w.DisplayFilter())
				}

				FilterWidget.SetValue(newFilter, app)
				RequestNewFilter(newFilter, app)

			},
			CopyModeWidget: CopyModeWidget,
			ChunkClicker:   streamClicker{},
			ErrorHandler:   simpleOnError{},
		})
}

//======================================================================

func openStreamUi(swid *streamwidget.Widget, app gowid.IApp) {
	streamViewNoKeysHolder.SetSubWidget(swid, app)
	appViewNoKeys.SetSubWidget(streamView, app)
	// When opening, put focus on the list of stream chunks. There may be none in which case
	// this won't work. But when UI is constructed, there are no chunks, even though it's not
	// open yet, so focus on the pile goes to the bottom, even when the chunk table becomes populated.
	// That's not ideal.
	swid.SetFocusOnChunksIfPossible(app)
}

func closeStreamUi(app gowid.IApp, refocus bool) {
	appViewNoKeys.SetSubWidget(mainView, app)

	// Do this if the user starts reassembly from the menu - better UX
	if refocus {
		setFocusOnPacketList(app)
	}
}

//======================================================================

func buildStreamUi() {
	conversationMenuHolder, conversationMenu = streamwidget.MakeConvMenu(&multiMenu1Opener)

	streamViewNoKeysHolder = holder.New(null.New())

	streamView = appkeys.New(
		appkeys.New(
			appkeys.New(
				streamViewNoKeysHolder,
				streamKeyPress,
			),
			copyModeExitKeys20,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		copyModeEnterKeys,
	)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
