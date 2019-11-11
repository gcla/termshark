// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark"
	"github.com/gcla/termshark/pcap"
	"github.com/gcla/termshark/pdmltree"
	"github.com/gcla/termshark/streams"
	"github.com/gcla/termshark/widgets/appkeys"
	"github.com/gcla/termshark/widgets/streamwidget"
	"github.com/gdamore/tcell"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

var streamViewNoKeysHolder *holder.Widget
var streamView *appkeys.KeyWidget
var conversationMenu *menu.Widget
var conversationMenuHolder *holder.Widget

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

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageStreamCache) OnNewSource(closeMe chan<- struct{}) {
	clearStreamState()
	close(closeMe)
}

//======================================================================

func streamKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	if evk.Rune() == 'q' || evk.Rune() == 'Q' || evk.Key() == tcell.KeyEscape {
		closeStreamUi(app, true)
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
	PcapScheduler.RequestNewFilter(filter, MakePacketViewUpdater(app))

	currentStreamKey = &streamKey{proto: proto, idx: streamIndex.Val()}

	// we maintain an lru.Cache of stream widgets so that we can quickly re-open
	// the UI for streams that have been calculated before.
	if streamWidgets == nil {
		initStreamWidgetCache()
	}

	var swid *streamwidget.Widget
	swid2, ok := streamWidgets.Get(*currentStreamKey)

	if ok {
		swid = swid2.(*streamwidget.Widget)
	} else {
		swid = makeStreamWidget(previousFilterValue, filter, Loader.String(), proto)
		streamWidgets.Add(*currentStreamKey, swid)
	}

	if swid.Finished() {
		openStreamUi(swid, app)
	} else {
		// Use the source context. At app shutdown, canceling main will cancel src which will cancel the stream
		// loader. And changing source should also cancel the stream loader on all occasions.
		StreamLoader = streams.NewLoader(streams.MakeCommands(), Loader.SourceContext())

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
	stop             chan struct{}
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

func (t *streamParseHandler) BeforeBegin(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenPleaseWait(appView, t.app)
	}))

	t.tick = time.NewTicker(time.Duration(200) * time.Millisecond)
	t.stop = make(chan struct{})

	termshark.TrackedGo(func() {
	Loop:
		for {
			select {
			case <-t.tick.C:
				t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
					pleaseWaitSpinner.Update()
				}))
			case <-t.stop:
				break Loop
			}
		}
	}, Goroutinewg)
}

func (t *streamParseHandler) AfterIndexEnd(success bool, closeMe chan<- struct{}) {
	close(closeMe)
	t.wid.SetFinished(true)
}

func (t *streamParseHandler) AfterEnd(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(t.app)
		}
		if !t.openedStreams {
			openStreamUi(t.wid, app)
			t.openedStreams = true
		}

		if t.wid.NumChunks() == 0 {
			OpenMessage("No stream payloads found.", appView, app)
		}
	}))
	close(t.stop)
}

func (t *streamParseHandler) TrackPayloadPacket(packet int) {
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		t.wid.TrackPayloadPacket(packet)
	}))
}

func (t *streamParseHandler) OnStreamHeader(hdr streams.FollowHeader, ch chan struct{}) {
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		t.wid.AddHeader(hdr)
	}))
	close(ch)
}

// Handle a line/chunk of input - one piece of reassembled data, which comes with
// a client/server direction.
func (t *streamParseHandler) OnStreamChunk(chunk streams.IChunk, ch chan struct{}) {
	t.Lock()
	defer t.Unlock()

	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(t.app)
		}
	}))

	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		t.wid.AddChunkEntire(chunk, app)
	}))

	// Do after adding chunk so I can set focus on chunks correctly
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.openedStreams {
			appViewNoKeys.SetSubWidget(streamView, app)
			openStreamUi(t.wid, app)
			t.openedStreams = true
		}
	}))

	close(ch)
}

func (t *streamParseHandler) OnError(err error, closeMe chan<- struct{}) {
	close(closeMe)
	log.Error(err)
	if !Running {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		QuitRequestedChan <- struct{}{}
	} else {

		var errstr string
		if kverr, ok := err.(gowid.KeyValueError); ok {
			errstr = fmt.Sprintf("%v\n\n", kverr.Cause())
			kvs := make([]string, 0, len(kverr.KeyVals))
			for k, v := range kverr.KeyVals {
				kvs = append(kvs, fmt.Sprintf("%v: %v", k, v))
			}
			errstr = errstr + strings.Join(kvs, "\n")
		} else {
			errstr = fmt.Sprintf("%v", err)
		}

		t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
			OpenError(errstr, app)
		}))
	}
}

func initStreamWidgetCache() {
	widgetCacheSize := termshark.ConfInt("main.stream-cache-size", 100)

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
				OpenMessage(fmt.Sprintf("Selected packet %d.", pkt+1), appView, app)
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
		conversationMenu, conversationMenuHolder,
		streamwidget.Options{
			DefaultDisplay: func() streamwidget.DisplayFormat {
				view := streamwidget.Hex
				choice := termshark.ConfString("main.stream-view", "hex")
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
				PcapScheduler.RequestNewFilter(newFilter, MakePacketViewUpdater(app))

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
	conversationMenuHolder, conversationMenu = streamwidget.MakeConvMenu()

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
