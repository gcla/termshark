// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package streamwidget provides a very specific stream reassembly termshark widget.
// This is probably not much use generally, but is separated out to ease testing. It
// is intended to render as mostly full screen, with a title bar, the main view showing
// the reassembled stream, and controls at the bottom.
package streamwidget

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/radio"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/gcla/termshark/v2/pkg/streams"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gcla/termshark/v2/ui/tableutil"
	"github.com/gcla/termshark/v2/widgets"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetable"
	"github.com/gcla/termshark/v2/widgets/framefocus"
	"github.com/gcla/termshark/v2/widgets/keepselected"
	"github.com/gcla/termshark/v2/widgets/regexstyle"
	"github.com/gcla/termshark/v2/widgets/scrollabletable"
	"github.com/gcla/termshark/v2/widgets/trackfocus"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

var fixed gowid.RenderFixed
var indentRe *regexp.Regexp

func init() {
	indentRe = regexp.MustCompile(`(?m)^(.+)$`) // do each line
}

var PacketRowNotLoadedError = fmt.Errorf("The packet is not yet loaded.")

//======================================================================

type DisplayFormat int

const (
	Hex   DisplayFormat = 0
	Ascii DisplayFormat = iota
	Raw   DisplayFormat = iota
)

type ConversationFilter int

const (
	Entire     ConversationFilter = 0
	ClientOnly ConversationFilter = iota
	ServerOnly ConversationFilter = iota
)

type streamStats struct {
	started       bool
	lastTurn      streams.Direction
	turns         int // how many times the conversation flips
	clientPackets int
	clientBytes   int
	serverPackets int
	serverBytes   int
}

type Options struct {
	DefaultDisplay func() DisplayFormat         // Start in ascii, hex, raw
	FilterOutFunc  func(IFilterOut, gowid.IApp) // UI changes to run when user clicks "filter out" button
	PreviousFilter string                       // so if we filter out, we can do "Previous and (! tcp.stream eq 0)"
	ChunkClicker   IChunkClicked                // UI changes to make when stream chunk in table is clicked
	ErrorHandler   IOnError                     // UI action to take on error
	CopyModeWidget gowid.IWidget                // What to display when copy-mode is started.
	MenuOpener     menu.IOpener                 // For integrating with UI app - the menu needs to be told what's underneath when opened
}

//======================================================================

type Widget struct {
	gowid.IWidget
	opt            Options
	tblWidgets     []*copymodetable.Widget // the table for all data, client data, server data
	viewWidgets    []gowid.IWidget         // the table for all data, client data, server data
	selectedConv   ConversationFilter      // both sides (entire), client only, server only
	data           *Data                   // the rest of the data from tshark -z follow
	stats          streamStats             // track turns, client packets, bytes, etc
	streamHeader   streams.FollowHeader    // first chunk of data back from tshark -z follow
	displayAs      DisplayFormat           // display as hex, ascii, raw
	captureDevice  string                  // it's a very feature-specific widget so I don't care about supporting callbacks
	displayFilter  string                  // "tcp.stream eq 1"
	Proto          streams.Protocol        // TCP, UDP
	tableHolder    *holder.Widget          // hold the chunk UI table
	convBtn        *button.Widget          // "Entire conversation" -> click this to open conv menu
	turnTxt        *text.Widget            // "26 clients pkts, 0 server pkts, 5 turns"
	sections       *pile.Widget            // the vertical ui layout
	convMenuHolder *holder.Widget          // actually holds the listbox used for the open "menu" - entire, client, server
	convMenu       *menu.Widget            // the menu that opens when you hit the conversation button (entire, client, server)
	clickActive    bool                    // if true, clicking in stream list will display packet selected
	keyState       *termshark.KeyState     // for vim key chords that are intended for table navigation
	doMenuUpdate   bool                    // Set to true if new data has arrived and the menu needs to be regenerated. Do this
	// because if I regenerate each click, I lose the list state which shows the item I last clicked on.
	searchState // track the current highlighted search term
}

func New(displayFilter string, captureDevice string, proto streams.Protocol,
	convMenu *menu.Widget, convMenuHolder *holder.Widget, keyState *termshark.KeyState,
	opts ...Options) *Widget {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	var mode DisplayFormat
	if opt.DefaultDisplay != nil {
		mode = opt.DefaultDisplay()
	}

	if opt.MenuOpener == nil {
		opt.MenuOpener = menu.OpenerFunc(widgets.OpenSimpleMenu)
	}

	res := &Widget{
		opt:            opt,
		displayFilter:  displayFilter,
		captureDevice:  captureDevice,
		Proto:          proto,
		displayAs:      mode,
		convMenu:       convMenu,
		convMenuHolder: convMenuHolder,
		tblWidgets:     make([]*copymodetable.Widget, 3),
		viewWidgets:    make([]gowid.IWidget, 3),
		clickActive:    true,
		keyState:       keyState,
	}

	res.construct()

	return res
}

var _ gowid.IWidget = (*Widget)(nil)
var _ iHighlight = (*Widget)(nil)

func (w *Widget) PreviousFilter() string {
	return w.opt.PreviousFilter
}

func (w *Widget) DisplayFilter() string {
	return w.displayFilter
}

func (w *Widget) clickIsActive() bool {
	return w.clickActive
}

// Used by the stream chunk structures, which act as table models; they apply the returned highlight structure
// to a a regexstyle which wraps the contents of each chunk displayed in the table. If this row is not the row
// currently being searched (e.g. chunk #5 instead of chunk #2), then a default Highlight is returned which
// will have no effect on the rendering of the stream chunk.
func (w *Widget) highlightThis(pos table.Position) regexstyle.Highlight {
	if pos == w.searchRow {
		return regexstyle.Highlight{
			Re:    w.searchRe,
			Occ:   w.searchOccurrence,
			Style: gowid.MakePaletteRef("stream-match"),
		}
	}
	return regexstyle.Highlight{}
}

// The widget displayed in the first line of the stream reassembly UI.
func (w *Widget) makeHeaderWidget() gowid.IWidget {
	var headerText string
	var headerText1 string
	var headerText2 string
	var headerText3 string
	if w.Proto != streams.Unspecified {
		headerText1 = fmt.Sprintf("Follow %s Stream", w.Proto)
	}
	if w.displayFilter != "" {
		headerText2 = fmt.Sprintf("(%s)", w.displayFilter)
	}
	if w.captureDevice != "" {
		headerText3 = fmt.Sprintf("- %s", w.captureDevice)
	}
	headerText = strings.Join([]string{headerText1, headerText2, headerText3}, " ")

	headerView := overlay.New(
		hpadding.New(w.opt.CopyModeWidget, gowid.HAlignMiddle{}, fixed),
		hpadding.New(
			text.New(headerText),
			gowid.HAlignMiddle{},
			fixed,
		),
		gowid.VAlignTop{},
		gowid.RenderWithRatio{R: 1},
		gowid.HAlignMiddle{},
		gowid.RenderWithRatio{R: 1},
		overlay.Options{
			BottomGetsFocus:  true,
			TopGetsNoFocus:   true,
			BottomGetsCursor: true,
		},
	)

	return headerView
}

func MakeConvMenu(opener menu.IOpener) (*holder.Widget, *menu.Widget) {
	convListBoxWidgetHolder := holder.New(null.New())

	convMenu := menu.New("conv", convListBoxWidgetHolder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	return convListBoxWidgetHolder, convMenu
}

func (w *Widget) updateConvMenuWidget(app gowid.IApp) {
	convListBox, _ := w.makeConvMenuWidget()
	w.convMenuHolder.SetSubWidget(convListBox, app)
	w.setConvButtonText(app)
	w.setTurnText(app)
	w.doMenuUpdate = false
}

func (w *Widget) makeConvMenuWidget() (gowid.IWidget, int) {
	savedItems := make([]menuutil.SimpleMenuItem, 0)

	savedItems = append(savedItems,
		menuutil.SimpleMenuItem{
			Txt: w.getConvButtonText(Entire),
			Key: gowid.MakeKey('e'),
			CB: func(app gowid.IApp, w2 gowid.IWidget) {
				w.opt.MenuOpener.CloseMenu(w.convMenu, app)
				w.selectedConv = Entire
				w.tableHolder.SetSubWidget(w.viewWidgets[w.selectedConv], app)
				w.setConvButtonText(app)
			},
		},
	)

	// Ensure we have valid header data. This should always be true
	if w.streamHeader.Node0 != "" && w.streamHeader.Node1 != "" {
		savedItems = append(savedItems,
			menuutil.SimpleMenuItem{
				Txt: w.getConvButtonText(ClientOnly),
				Key: gowid.MakeKey('c'),
				CB: func(app gowid.IApp, w2 gowid.IWidget) {
					w.opt.MenuOpener.CloseMenu(w.convMenu, app)
					w.selectedConv = ClientOnly
					w.tableHolder.SetSubWidget(w.viewWidgets[w.selectedConv], app)
					w.setConvButtonText(app)
				},
			},
		)

		savedItems = append(savedItems,
			menuutil.SimpleMenuItem{
				Txt: w.getConvButtonText(ServerOnly),
				Key: gowid.MakeKey('s'),
				CB: func(app gowid.IApp, w2 gowid.IWidget) {
					w.opt.MenuOpener.CloseMenu(w.convMenu, app)
					w.selectedConv = ServerOnly
					w.tableHolder.SetSubWidget(w.viewWidgets[w.selectedConv], app)
					w.setConvButtonText(app)
				},
			},
		)
	}

	return menuutil.MakeMenuWithHotKeys(savedItems, nil)
}

// Turns an array of stream chunks into a pair of (a) a scrollable table
// widget to be displayed, and (b) the underlying table so that its model
// can be manipulated.
func (w *Widget) makeTable(i int) (gowid.IWidget, *copymodetable.Widget) {
	data := w.data.vdata[i].hexChunks

	btbl := &table.BoundedWidget{Widget: table.New(data)}

	cmtbl := copymodetable.New(
		btbl,
		data,
		data,
		"streamtable",
		copyModePalette{},
	)
	sc := appkeys.New(
		keepselected.New(
			withscrollbar.New(
				scrollabletable.New(cmtbl),
				withscrollbar.Options{
					HideIfContentFits: true,
				},
			),
		),
		tableutil.GotoHandler(&tableutil.GoToAdapter{
			BoundedWidget: btbl,
			KeyState:      w.keyState,
		}),
	)

	return sc, cmtbl
}

// "26 clients pkts, 0 server pkts, 5 turns"
func (w *Widget) getTurnContent() *text.Content {
	cpkts := gwutil.If(w.stats.clientPackets == 1, "pkt", "pkts").(string)
	spkts := gwutil.If(w.stats.serverPackets == 1, "pkt", "pkts").(string)
	turns := gwutil.If(w.stats.turns == 1, "turn", "turns").(string)

	return text.NewContent([]text.ContentSegment{
		text.StyledContent(fmt.Sprintf("%d client %s", w.stats.clientPackets, cpkts), gowid.MakePaletteRef("stream-client")),
		text.StringContent(", "),
		text.StyledContent(fmt.Sprintf("%d server %s", w.stats.serverPackets, spkts), gowid.MakePaletteRef("stream-server")),
		text.StringContent(fmt.Sprintf(", %d %s", w.stats.turns, turns)),
	})
}

func (w *Widget) setTurnText(app gowid.IApp) {
	w.turnTxt.SetContent(app, w.getTurnContent())
}

func (w *Widget) getConvButtonText(typ ConversationFilter) string {
	var txt string
	switch typ {
	case Entire:
		txt = fmt.Sprintf("Entire conversation (%d bytes)", w.stats.clientBytes+w.stats.serverBytes)
	case ClientOnly:
		txt = fmt.Sprintf("%s → %s (%d bytes)", w.streamHeader.Node0, w.streamHeader.Node1, w.stats.clientBytes)
	case ServerOnly:
		txt = fmt.Sprintf("%s → %s (%d bytes)", w.streamHeader.Node1, w.streamHeader.Node0, w.stats.serverBytes)
	}

	return txt
}

// Set the text of the button showing "entire conversation", client only, server only
func (w *Widget) setConvButtonText(app gowid.IApp) {
	w.convBtn.SetSubWidget(text.New(w.getConvButtonText(w.selectedConv)), app)
}

func (w *Widget) construct() {

	w.data = newData(w.opt.ChunkClicker, w, w, w)

	fixed := fixed

	rbgroup := make([]radio.IWidget, 0)
	rb1 := radio.New(&rbgroup)
	rbt1 := text.New(" hex ")
	rb2 := radio.New(&rbgroup)
	rbt2 := text.New(" ascii ")
	rb3 := radio.New(&rbgroup)
	rbt3 := text.New(" raw ")

	switch w.displayAs {
	case Hex:
		rb1.Select(nil)
	case Ascii:
		rb2.Select(nil)
	default:
		rb3.Select(nil)
	}

	c2cols := []gowid.IContainerWidget{
		&gowid.ContainerWidget{rb1, fixed},
		&gowid.ContainerWidget{rbt1, fixed},
		&gowid.ContainerWidget{rb2, fixed},
		&gowid.ContainerWidget{rbt2, fixed},
		&gowid.ContainerWidget{rb3, fixed},
		&gowid.ContainerWidget{rbt3, fixed},
	}
	cols2 := columns.New(c2cols)

	rb1.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		if rb1.Selected {
			w.displayAs = Hex
			for i := 0; i < len(w.tblWidgets); i++ {
				w.updateChunkModel(i, w.displayAs, app)
			}
			profiles.SetConf("main.stream-view", "hex")
		}
	}})
	rb2.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		if rb2.Selected {
			w.displayAs = Ascii
			for i := 0; i < len(w.tblWidgets); i++ {
				w.updateChunkModel(i, w.displayAs, app)
			}
			profiles.SetConf("main.stream-view", "ascii")
		}
	}})
	rb3.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		if rb3.Selected {
			w.displayAs = Raw
			for i := 0; i < len(w.tblWidgets); i++ {
				w.updateChunkModel(i, w.displayAs, app)
			}
			profiles.SetConf("main.stream-view", "raw")
		}
	}})

	filterOutBtn := button.New(text.New("Filter stream out"))
	filterOutBtn.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.opt.FilterOutFunc(w, app)
	}})

	w.turnTxt = text.NewFromContent(w.getTurnContent())

	// Hardcoded for 3 lines + frame - yuck
	convBtnSite := menu.NewSite(menu.SiteOptions{YOffset: -5})
	w.convBtn = button.New(text.New(w.getConvButtonText(Entire)))
	w.convBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		if w.doMenuUpdate {
			w.updateConvMenuWidget(app)
		}
		w.opt.MenuOpener.OpenMenu(w.convMenu, convBtnSite, app)
	}))
	//styledConvBtn := styled.NewInvertedFocus(w.convBtn, gowid.MakePaletteRef("default"))
	styledConvBtn := styled.NewExt(
		w.convBtn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	// After making button
	w.doMenuUpdate = true

	convCols := columns.NewFixed(convBtnSite, styledConvBtn)

	searchBox := edit.New(edit.Options{
		Caption: "Find: ",
	})

	reCheck := checkbox.New(false)
	caseCheck := checkbox.New(true)

	nextClick := func(app gowid.IApp, w2 gowid.IWidget) {
		txt := searchBox.Text()

		if txt == "" {
			w.opt.ErrorHandler.OnError("Enter a search string.", app)
			return
		}

		if !reCheck.IsChecked() {
			txt = regexp.QuoteMeta(txt)
		}
		if !caseCheck.IsChecked() {
			txt = fmt.Sprintf("(?i)%s", txt)
		}

		newre, err := regexp.Compile(txt)
		if err != nil {
			w.opt.ErrorHandler.OnError(fmt.Sprintf("Invalid regex: %s", searchBox.Text()), app)
			return
		}

		if w.searchReTxt != txt {
			w.initSearch(newre, txt)
		}

		i := w.selectedConv

		w.tblWidgets[i].Cache().Purge()

		// Start from current table focus position
		w.searchRow = table.Position(w.tblWidgets[i].Focus().(list.IBoundedWalkerPosition).ToInt())

		origstate := w.searchState

		searchDone := false
		fixTablePosition := false

		for !searchDone {
			rem := findMatcher(w.tblWidgets[i].At(w.searchRow))
			if rem == nil {
				searchDone = true
				w.searchState = origstate // maintain old position
			} else {

				if w.maxOccurrences.IsNone() {
					w.maxOccurrences = gwutil.SomeInt(rem.RegexMatches())
					if w.maxOccurrences.Value() == 0 {
						w.goToNextSearchRow()
						fixTablePosition = true
						continue
					}
					w.searchOccurrence = 0
					searchDone = true
				} else if w.searchOccurrence < w.maxOccurrences.Val()-1 {
					w.searchOccurrence += 1
					searchDone = true
				} else {
					w.goToNextSearchRow()
					fixTablePosition = true
					continue
				}
			}
		}

		w.tblWidgets[i].Cache().Purge()

		if fixTablePosition {
			w.tblWidgets[i].SetCurrentRow(w.searchRow)
		}

	}

	searchBox2 := appkeys.New(
		searchBox,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			res := false
			switch ev.Key() {
			case tcell.KeyEnter:
				nextClick(app, nil)
				res = true
			}
			return res
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	searchBoxStyled := styled.New(searchBox2,
		gowid.MakePaletteRef("stream-search"),
	)

	nextBtn := button.New(text.New("Next"))
	nextBtn.OnClick(gowid.MakeWidgetCallback("cb", nextClick))

	pad := text.New(" ")
	hpad := hpadding.New(pad, gowid.HAlignLeft{}, fixed)

	vline := &gowid.ContainerWidget{
		IWidget: fill.New('|'),
		D:       gowid.RenderWithUnits{U: 1},
	}

	streamsFooter1 := columns.NewWithDim(
		fixed,
		hpad,
		hpadding.New(
			w.turnTxt,
			gowid.HAlignLeft{},
			fixed,
		),
		hpad,
		vline,
		hpad,
		&gowid.ContainerWidget{
			IWidget: searchBoxStyled,
			D:       gowid.RenderWithWeight{W: 1},
		},
		hpad,
		hpadding.New(
			clicktracker.New(
				styled.NewExt(
					nextBtn,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
			),
			gowid.HAlignLeft{},
			fixed,
		),
		hpad,
		vline,
		hpad,
		reCheck,
		hpad,
		text.New("Regex"),
		hpad,
		caseCheck,
		hpad,
		text.New("Case"),
		hpad,
	)

	streamsFooter := columns.NewWithDim(
		gowid.RenderWithWeight{1},
		hpadding.New(
			convCols,
			gowid.HAlignMiddle{},
			fixed,
		),
		hpadding.New(
			cols2,
			gowid.HAlignMiddle{},
			fixed,
		),
		hpadding.New(
			//styled.NewInvertedFocus(filterOutBtn, gowid.MakePaletteRef("default")),
			styled.NewExt(
				filterOutBtn,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
			gowid.HAlignMiddle{},
			fixed,
		),
	)

	// In case it's not made
	header := w.makeHeaderWidget()
	//w.headerHolder = holder.New(w.header)

	streamsHeader := columns.NewWithDim(
		gowid.RenderWithWeight{1},
		//w.headerHolder,
		header,
	)

	w.tableHolder = holder.New(null.New())

	mainpane := trackfocus.New(
		styled.New(
			framed.NewUnicode(
				w.tableHolder,
			),
			gowid.MakePaletteRef("mainpane"),
		),
	)

	// Track whether the stream chunk list has focus. If it is clicked when it doesn't have focus,
	// don't annoy the user by displaying the selected packet in the underlying packet list. We
	// assume the user is just clicking to change the focus.
	mainpane.OnFocusLost(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.clickActive = false
	}))

	mainpane.OnFocusGained(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.clickActive = true
	}))

	mainPaneWithKeys := appkeys.NewMouse(
		appkeys.New(
			mainpane,
			widgets.SwallowMovementKeys,
		),
		widgets.SwallowMouseScroll, // So we don't scroll out of the stream chunk list - it's annoying. Use tab instead.
	)

	streamView := pile.New(
		[]gowid.IContainerWidget{
			&gowid.ContainerWidget{
				streamsHeader,
				gowid.RenderWithUnits{U: 1},
			},
			&gowid.ContainerWidget{
				mainPaneWithKeys,
				gowid.RenderWithWeight{W: 1},
			},
			&gowid.ContainerWidget{
				streamsFooter1,
				gowid.RenderWithUnits{U: 1},
			},
			&gowid.ContainerWidget{
				divider.NewUnicode(),
				gowid.RenderFlow{},
			},
			&gowid.ContainerWidget{
				streamsFooter,
				gowid.RenderWithUnits{U: 1},
			},
		},
	)

	streamViewWithKeysAfter := appkeys.New(
		streamView,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			return streamViewKeyPressAfter(streamView, ev, app)
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	w.sections = streamView
	w.IWidget = streamViewWithKeysAfter

	for i := 0; i < len(w.tblWidgets); i++ {
		j := i // avoid loop variable gotcha
		w.viewWidgets[i], w.tblWidgets[i] = w.makeTable(i)

		w.tblWidgets[i].OnFocusChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
			// reset search on manual moving of table
			w.goToSearchRow(table.Position(w.tblWidgets[j].Focus().(list.IBoundedWalkerPosition).ToInt()))
		}))

		w.updateChunkModel(i, w.displayAs, nil)
	}

	w.tableHolder.SetSubWidget(w.viewWidgets[w.selectedConv], nil)
}

func (w *Widget) updateChunkModel(i int, f DisplayFormat, app gowid.IApp) {
	switch f {
	case Hex:
		w.tblWidgets[i].SetModel(w.data.vdata[i].hexChunks, app)
		w.tblWidgets[i].RowClip = w.data.vdata[i].hexChunks
		w.tblWidgets[i].AllClip = w.data.vdata[i].hexChunks
	case Ascii:
		w.tblWidgets[i].SetModel(w.data.vdata[i].asciiChunks, app)
		w.tblWidgets[i].RowClip = w.data.vdata[i].asciiChunks
		w.tblWidgets[i].AllClip = w.data.vdata[i].asciiChunks
	case Raw:
		w.tblWidgets[i].SetModel(w.data.vdata[i].rawChunks, app)
		w.tblWidgets[i].RowClip = w.data.vdata[i].rawChunks
		w.tblWidgets[i].AllClip = w.data.vdata[i].rawChunks
	}
}

//======================================================================

type iMatcher interface {
	RegexMatches() int          // the number of times the regex matchesd in the data
	SetRegexOccurrence(i int)   // highlight the ith occurrence of the match
	SetRegex(re *regexp.Regexp) // use this regular expression
}

// A utility to find the regex matching widget within the stream reassembly table
// widget hierarchy.
func findMatcher(w gowid.IWidget) iMatcher {
	res := gowid.FindInHierarchy(w, true, gowid.WidgetPredicate(func(w gowid.IWidget) bool {
		var res bool
		if _, ok := w.(iMatcher); ok {
			res = true
		}
		return res
	}))

	if res == nil {
		return nil
	} else {
		return res.(iMatcher)
	}
}

func (w *Widget) TrackPayloadPacket(packet int) {
	w.data.pktIndices = append(w.data.pktIndices, packet)
}

func (w *Widget) NumChunks() int {
	return len(w.data.vdata[Entire].hexChunks.chunks)
}

func (w *Widget) Finished() bool {
	return w.data.finished
}

func (w *Widget) SetFinished(f bool) {
	w.data.finished = f
}

func (w *Widget) SetFocusOnChunksIfPossible(app gowid.IApp) {
	if w.NumChunks() == 0 {
		w.sections.SetFocus(app, 4)
	} else {
		w.sections.SetFocus(app, 1)
	}
}

func (w *Widget) SetCurrentRow(row table.Position) {
	w.tblWidgets[w.selectedConv].SetCurrentRow(row)
}

func (w *Widget) GoToMiddle(app gowid.IApp) {
	w.tblWidgets[w.selectedConv].GoToMiddle(app)
}

// Hardcoded - yuck!
func setFocusOnSearchBox(app gowid.IApp, view gowid.IWidget) {
	gowid.SetFocusPath(view, []interface{}{2, 5}, app)
}

func streamViewKeyPressAfter(sections *pile.Widget, evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false

	if evk.Key() == tcell.KeyTAB {
		if next, ok := sections.FindNextSelectable(gowid.Forwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	} else if evk.Key() == tcell.KeyBacktab {
		if next, ok := sections.FindNextSelectable(gowid.Backwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	} else if evk.Rune() == '/' {
		setFocusOnSearchBox(app, sections)
		handled = true
	}

	return handled
}

func (w *Widget) String() string {
	return "streamreassembly"
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return w.IWidget.UserInput(ev, size, focus, app)
}

func (w *Widget) AddHeader(hdr streams.FollowHeader, app gowid.IApp) {
	w.streamHeader = hdr
	w.doMenuUpdate = true
}

func (w *Widget) MapChunkToTableRow(chunk int) (int, error) {
	if chunk < len(w.data.vdata[w.selectedConv].subIndices) {
		gchunk := w.data.vdata[w.selectedConv].subIndices[chunk]
		if gchunk < len(w.data.pktIndices) {
			return w.data.pktIndices[gchunk], nil
		}
	}

	err := gowid.WithKVs(PacketRowNotLoadedError, map[string]interface{}{
		"row": chunk,
	})
	return -1, err
}

func (w *Widget) AddChunkEntire(ch streams.IChunk, app gowid.IApp) {

	dir := ch.Direction()

	if w.stats.lastTurn != dir && w.stats.started {
		w.stats.turns++
	}
	w.stats.lastTurn = dir
	w.stats.started = true

	switch dir {
	case streams.Client:
		w.stats.clientPackets++
		w.stats.clientBytes += len(ch.StreamData())
	case streams.Server:
		w.stats.serverPackets++
		w.stats.serverBytes += len(ch.StreamData())
	}

	w.data.vdata[Entire].hexChunks.chunks = append(w.data.vdata[Entire].hexChunks.chunks, ch)
	w.data.vdata[Entire].update()
	w.data.vdata[Entire].subIndices = append(w.data.vdata[Entire].subIndices, w.data.currentChunk)

	switch dir {
	case streams.Client:
		w.data.vdata[ClientOnly].hexChunks.chunks = append(w.data.vdata[ClientOnly].hexChunks.chunks, ch)
		w.data.vdata[ClientOnly].update()
		w.data.vdata[ClientOnly].subIndices = append(w.data.vdata[ClientOnly].subIndices, w.data.currentChunk)
	case streams.Server:
		w.data.vdata[ServerOnly].hexChunks.chunks = append(w.data.vdata[ServerOnly].hexChunks.chunks, ch)
		w.data.vdata[ServerOnly].update()
		w.data.vdata[ServerOnly].subIndices = append(w.data.vdata[ServerOnly].subIndices, w.data.currentChunk)
	}

	// Update the copymodetable's data - otherwise the slice is stale

	for i := 0; i < len(w.tblWidgets); i++ { // Loop over all conmv views - entire, client, server
		w.updateChunkModel(i, w.displayAs, app)
	}

	w.updateConvMenuWidget(app)

	w.data.currentChunk++
}

//======================================================================

type iClickIsActive interface {
	clickIsActive() bool
}

type iHighlight interface {
	highlightThis(pos table.Position) regexstyle.Highlight
}

type IFilterOut interface {
	PreviousFilter() string
	DisplayFilter() string
}

type IOnError interface {
	OnError(msg string, app gowid.IApp)
}

type iMapChunkToTableRow interface {
	MapChunkToTableRow(chunk int) (int, error)
}

// Supplied by user of widget - what UI changes to make when packet is clicked
type IChunkClicked interface {
	OnPacketClicked(pkt int, app gowid.IApp) error
	HandleError(row table.RowId, err error, app gowid.IApp)
}

// Used by widget - first map table click to packet number, then use IChunkClicked
type iChunkClicker interface {
	IChunkClicked
	iClickIsActive
	iMapChunkToTableRow
	iHighlight
}

type chunkList struct {
	clicker iChunkClicker
	chunks  []streams.IChunk
}

type asciiChunkList struct {
	*chunkList
}

type rawChunkList struct {
	*chunkList
}

var _ table.IBoundedModel = chunkList{}
var _ table.IBoundedModel = asciiChunkList{}
var _ table.IBoundedModel = rawChunkList{}
var _ copymodetable.IRowCopier = chunkList{}
var _ copymodetable.IRowCopier = asciiChunkList{}
var _ copymodetable.IRowCopier = rawChunkList{}
var _ copymodetable.ITableCopier = chunkList{}
var _ copymodetable.ITableCopier = asciiChunkList{}
var _ copymodetable.ITableCopier = rawChunkList{}

// CopyTable is here to implement copymodetable.IRowCopier
func (c chunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	hexd := format.HexDump(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy hexdump",
			Val:  hexd,
		},
	}
}

func (c asciiChunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	prt := format.MakePrintableStringWithNewlines(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy ascii",
			Val:  prt,
		},
	}
}

func (c rawChunkList) CopyRow(rowid table.RowId) []gowid.ICopyResult {
	raw := format.MakeHexStream(c.chunks[int(rowid)].StreamData())

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy raw",
			Val:  raw,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c asciiChunkList) CopyTable() []gowid.ICopyResult {
	prtl := make([]string, 0, len(c.chunks))

	for i := 0; i < len(c.chunks); i++ {
		prtl = append(prtl, format.MakePrintableStringWithNewlines(c.chunks[i].StreamData()))
	}

	prt := strings.Join(prtl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy ascii",
			Val:  prt,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c chunkList) CopyTable() []gowid.ICopyResult {
	hexdl := make([]string, 0, len(c.chunks))

	for i := 0; i < len(c.chunks); i++ {
		hex := format.HexDump(c.chunks[i].StreamData())
		if c.chunks[i].Direction() == streams.Server {
			hex = indentRe.ReplaceAllString(hex, `    $1`)
		}

		hexdl = append(hexdl, hex)
	}

	hexd := strings.Join(hexdl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy hexdump",
			Val:  hexd,
		},
	}
}

// CopyTable is here to implement copymodetable.ITableCopier
func (c rawChunkList) CopyTable() []gowid.ICopyResult {
	rawl := make([]string, 0, len(c.chunks))

	for i := 0; i < len(c.chunks); i++ {
		rawl = append(rawl, format.MakeHexStream(c.chunks[i].StreamData()))
	}

	raw := strings.Join(rawl, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy raw",
			Val:  raw,
		},
	}
}

// makeButton constructs a row for the stream list that if clicked will select the
// appropriate packet in the packet list
func (c chunkList) makeButton(row table.RowId, ch gowid.IWidget) *button.Widget {
	btn := button.NewBare(ch)

	//btn.OnClickDown(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
	btn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		if c.clicker != nil && c.clicker.clickIsActive() {
			if irow, err := c.clicker.MapChunkToTableRow(int(row)); err != nil {
				c.clicker.HandleError(row, err, app)
			} else {
				c.clicker.OnPacketClicked(irow, app)
			}
		}
	}),
	)

	return btn
}

func (c chunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	var ch gowid.IWidget

	// not sorted
	hilite := c.clicker.highlightThis(table.Position(row))

	datastr := format.HexDump(c.chunks[row].StreamData())
	if c.chunks[row].Direction() == streams.Server {
		datastr = indentRe.ReplaceAllString(datastr, `    $1`)
	}

	dataw := framefocus.New(
		selectable.New(
			regexstyle.New(
				text.New(datastr),
				hilite,
			),
		),
	)

	if c.chunks[row].Direction() == streams.Client {
		ch = styled.New(
			dataw,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			dataw,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

//======================================================================

func (c asciiChunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	hl := c.clicker.highlightThis(table.Position(row))

	str := framefocus.NewSlim(
		selectable.New(
			regexstyle.New(
				text.New(strings.TrimSuffix(format.MakePrintableStringWithNewlines((*c.chunkList).chunks[row].StreamData()), "\n")),
				hl,
			),
		),
	)

	var ch gowid.IWidget

	if (*c.chunkList).chunks[row].Direction() == streams.Client {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

func (c rawChunkList) CellWidgets(row table.RowId) []gowid.IWidget {
	res := make([]gowid.IWidget, 1)

	hl := c.clicker.highlightThis(table.Position(row))

	str := framefocus.New(
		selectable.New(
			regexstyle.New(
				text.New(format.MakeHexStream((*c.chunkList).chunks[row].StreamData())),
				hl,
			),
		),
	)

	var ch gowid.IWidget

	if (*c.chunkList).chunks[row].Direction() == streams.Client {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-client"),
		)
	} else {
		ch = styled.New(
			str,
			gowid.MakePaletteRef("stream-server"),
		)
	}

	res[0] = c.makeButton(row, ch)

	return res
}

func (c asciiChunkList) Widths() []gowid.IWidgetDimension {
	return []gowid.IWidgetDimension{gowid.RenderWithWeight{W: 1}}
}

func (c chunkList) Widths() []gowid.IWidgetDimension {
	return []gowid.IWidgetDimension{gowid.RenderWithWeight{W: 1}}
}

func (c chunkList) Columns() int {
	return 1
}

func (c chunkList) Rows() int {
	return len(c.chunks)
}

func (c chunkList) HorizontalSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) HeaderSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) HeaderWidgets() []gowid.IWidget {
	return nil
}

func (c chunkList) VerticalSeparator() gowid.IWidget {
	return nil
}

func (c chunkList) RowIdentifier(row int) (table.RowId, bool) {
	if row < 0 || row >= len(c.chunks) {
		return -1, false
	}
	return table.RowId(row), true
}

//======================================================================

// TODO - duplicated from termshark

type copyModePalette struct{}

var _ gowid.IClipboardSelected = copyModePalette{}

func (r copyModePalette) AlterWidget(w gowid.IWidget, app gowid.IApp) gowid.IWidget {
	return styled.New(w, gowid.MakePaletteRef("copy-mode"),
		styled.Options{
			OverWrite: true,
		},
	)
}

//======================================================================

type searchState struct {
	searchReTxt      string
	searchRe         *regexp.Regexp
	searchRow        table.Position
	searchOccurrence int
	maxOccurrences   gwutil.IntOption
}

func (s *searchState) initSearch(re *regexp.Regexp, txt string) {
	s.searchReTxt = txt
	s.searchRe = re
	s.searchRow = 0
}

func (s *searchState) goToSearchRow(row table.Position) {
	s.searchRow = row
	s.searchOccurrence = 0
	s.maxOccurrences = gwutil.NoneInt()
}

func (s *searchState) goToNextSearchRow() {
	s.goToSearchRow(s.searchRow + 1)
}

func (w searchState) String() string {
	return fmt.Sprintf("[re='%s' row=%d occ=%d maxocc=%v]", w.searchReTxt, w.searchRow, w.searchOccurrence, w.maxOccurrences)
}

//======================================================================

// Represents the view of the data from either both sides, client side or server side
type ViewData struct {
	subIndices  []int // [0,1,2,3,...] - index into pktIndices
	hexChunks   chunkList
	asciiChunks asciiChunkList
	rawChunks   rawChunkList
}

func newViewData(clicker IChunkClicked, ca iClickIsActive, mapper iMapChunkToTableRow, hiliter iHighlight) *ViewData {

	clickMapper := struct {
		IChunkClicked
		iClickIsActive
		iMapChunkToTableRow
		iHighlight
	}{
		IChunkClicked:       clicker,
		iClickIsActive:      ca,
		iMapChunkToTableRow: mapper,
		iHighlight:          hiliter,
	}

	res := &ViewData{
		subIndices: make([]int, 0, 16),
		hexChunks: chunkList{
			clicker: clickMapper,
			chunks:  make([]streams.IChunk, 0, 16),
		},
	}

	res.update()

	return res
}

func (v *ViewData) update() {
	v.asciiChunks = asciiChunkList{
		chunkList: &v.hexChunks,
	}
	v.rawChunks = rawChunkList{
		chunkList: &v.hexChunks,
	}
}

//======================================================================

// Represents all the streamed data
type Data struct {
	pktIndices   []int       // [0,2,5,12...] - frame numbers (-1) for each packet of this stream
	vdata        []*ViewData // for each of (a) whole view (b) client (c) server
	currentChunk int         // add to client or server view
	finished     bool
}

func newData(clicker IChunkClicked, ca iClickIsActive, mapper iMapChunkToTableRow, hiliter iHighlight) *Data {
	vdata := make([]*ViewData, 0, 3)
	for i := 0; i < 3; i++ {
		vdata = append(vdata, newViewData(clicker, ca, mapper, hiliter))
	}
	res := &Data{
		pktIndices: make([]int, 0, 16),
		vdata:      vdata,
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
