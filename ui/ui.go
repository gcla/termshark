// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gcla/deep"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/disable"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/progress"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/spinner"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/pkg/noroot"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/pkg/theme"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gcla/termshark/v2/ui/tableutil"
	"github.com/gcla/termshark/v2/widgets"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetree"
	"github.com/gcla/termshark/v2/widgets/enableselected"
	"github.com/gcla/termshark/v2/widgets/expander"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/hexdumper2"
	"github.com/gcla/termshark/v2/widgets/ifwidget"
	"github.com/gcla/termshark/v2/widgets/mapkeys"
	"github.com/gcla/termshark/v2/widgets/minibuffer"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/gcla/termshark/v2/widgets/rossshark"
	"github.com/gcla/termshark/v2/widgets/search"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	"github.com/gdamore/tcell/v2"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//======================================================================

var Goroutinewg *sync.WaitGroup

type WidgetOwner int

const (
	NoOwner WidgetOwner = iota
	LoaderOwns
	SearchOwns
)

// Global so that we can change the displayed packet in the struct view, etc
// test
var appViewNoKeys *holder.Widget
var appView *holder.Widget
var mbView *holder.Widget
var mainViewNoKeys *holder.Widget
var mainView *appkeys.KeyWidget
var pleaseWaitSpinner *spinner.Widget
var mainviewRows *resizable.PileWidget
var mainview gowid.IWidget
var altview1 gowid.IWidget
var altview1OuterRows *resizable.PileWidget
var altview1Pile *resizable.PileWidget
var altview1Cols *resizable.ColumnsWidget
var altview2 gowid.IWidget
var altview2OuterRows *resizable.PileWidget
var altview2Pile *resizable.PileWidget
var altview2Cols *resizable.ColumnsWidget
var viewOnlyPacketList *pile.Widget
var viewOnlyPacketStructure *pile.Widget
var viewOnlyPacketHex *pile.Widget
var filterCols *columns.Widget
var loadProg *columns.Widget
var loadStop *button.Widget
var searchProg *columns.Widget
var searchStop *button.Widget
var progWidgetIdx int
var mainviewPaths [][]interface{}
var altview1Paths [][]interface{}
var altview2Paths [][]interface{}
var maxViewPath []interface{}
var filterPathMain []interface{}
var filterPathAlt []interface{}
var filterPathMax []interface{}
var searchPathMain []interface{}
var searchPathAlt []interface{}
var searchPathMax []interface{}
var menuPathMain []interface{}
var menuPathAlt []interface{}
var menuPathMax []interface{}
var view1idx int
var view2idx int
var generalMenu *menu.Widget
var analysisMenu *menu.Widget
var savedMenu *menu.Widget
var profileMenu *menu.Widget
var FilterWidget *filter.Widget
var Fin *rossshark.Widget
var CopyModeWidget gowid.IWidget
var CopyModePredicate ifwidget.Predicate
var openMenuSite *menu.SiteWidget
var openAnalysisSite *menu.SiteWidget
var packetListViewHolder *holder.Widget
var packetListTable *table.BoundedWidget
var packetStructureViewHolder *holder.Widget
var packetHexViewHolder *holder.Widget
var progressHolder *holder.Widget
var progressOwner WidgetOwner
var stopCurrentSearch search.IRequestStop
var loadProgress *progress.Widget
var loadSpinner *spinner.Widget
var savedListBoxWidgetHolder *holder.Widget
var singlePacketViewMsgHolder *holder.Widget // either empty or "loading..."
var keyMapper *mapkeys.Widget

// For deconstructing the @showname PDML attribute into a short form for the UI
var shownameRe = regexp.MustCompile(`(.*?= )?([^:]+)`)

type MenuHolder struct {
	gowid.IMenuCompatible
}

var multiMenu *MenuHolder = &MenuHolder{}
var multiMenuWidget *holder.Widget
var multiMenu2 *MenuHolder = &MenuHolder{}
var multiMenu2Widget *holder.Widget
var multiMenu1Opener MultiMenuOpener
var multiMenu2Opener MultiMenuOpener

var tabViewsForward map[gowid.IWidget]gowid.IWidget
var tabViewsBackward map[gowid.IWidget]gowid.IWidget

var currentProfile *text.Widget
var currentProfileWidget *columns.Widget
var currentProfileWidgetHolder *holder.Widget
var openProfileSite *menu.SiteWidget

var currentCapture *text.Widget
var currentCaptureWidget *columns.Widget
var currentCaptureWidgetHolder *holder.Widget

var nullw *null.Widget // empty
var fillSpace *fill.Widget
var fillVBar *fill.Widget
var colSpace *gowid.ContainerWidget

var curPacketStructWidget *copymodetree.Widget
var packetHexWidgets *lru.Cache
var packetListView *psmlTableRowWidget

// Usually false. When the user moves the cursor in the hex widget, a callback will update the
// struct widget's current expansion. That results in a callback to the current hex widget to
// update its position - ad inf. The hex widget callback checks to see whether or not the hex
// widget has "focus". If it doesn't, the callback is suppressed - to short circuit the callback
// loop. BUT - after a packet search, we reposition the hex widget and want the callback from
// hex to struct to happen once. So this is a workaround to allow it in that case.
//
// This variable has two effects:
// - when the hex widget is positioned programmatically, and focus is not on the hex widget,
//   the struct widget is nevertheless updated accordingly
// - but when the struct widget is updated, if the innermost layer does not capture the
//   current hex location (the search destination), DON'T update the hex position to be
//   inside the PDML's innermost layer, which maybe somewhere else in the packet.
//
var allowHexToStructRepositioning bool

var filterWithSearch gowid.IWidget
var filterWithoutSearch gowid.IWidget
var filterHolder *holder.Widget
var SearchWidget *search.Widget

var Loadingw gowid.IWidget    // "loading..."
var MissingMsgw gowid.IWidget // centered, holding singlePacketViewMsgHolder
var EmptyStructViewTimer *time.Timer
var EmptyHexViewTimer *time.Timer

var curSearchPosition tree.IPos                   // e.g. [0, 4] -> the indices of the struct layer
var curExpandedStructNodes pdmltree.ExpandedPaths // a path to each expanded node in the packet, preserved while navigating
var curStructPosition tree.IPos                   // e.g. [0, 2, 1] -> the indices of the expanded nodes
var curPdmlPosition []string                      // e.g. [ , tcp, tcp.srcport ] -> the path from focus to root in the current struct
var curStructWidgetState interface{}              // e.g. {linesFromTop: 1, ...} -> the positioning of the current struct widget
var curColumnFilter string                        // e.g. tcp.port - updated as the user moves through the struct widget
var curColumnFilterName string                    // e.g. "TCP port" - from the showname attribute in the PDML
var curColumnFilterValue string                   // e.g. "80" - from the show attribute

var CacheRequests []pcap.LoadPcapSlice

var CacheRequestsChan chan struct{} // false means started, true means finished
var QuitRequestedChan chan struct{}
var StartUIChan chan struct{}
var StartUIOnce sync.Once

// Store this for vim-like keypresses that are a sequence e.g. "ZZ"
var keyState termshark.KeyState
var marksMap map[rune]termshark.JumpPos
var globalMarksMap map[rune]termshark.GlobalJumpPos
var lastJumpPos int

var NoGlobalJump termshark.GlobalJumpPos // leave as default, like a placeholder

var Loader *pcap.PacketLoader
var FieldCompleter *fields.TSharkFields // share this - safe once constructed

var WriteToSelected bool       // true if the user provided the -w flag
var WriteToDeleted bool        // true if the user deleted the temporary pcap before quitting
var DarkMode bool              // global state in app
var PacketColors bool          // global state in app
var PacketColorsSupported bool // global state in app - true if it's even possible
var AutoScroll bool            // true if the packet list should auto-scroll when listening on an interface.
var newPacketsArrived bool     // true if current updates are due to new packets when listening on an interface.
var reenableAutoScroll bool    // set to true by keypress processing widgets - used with newPacketsArrived
var Running bool               // true if gowid/tcell is controlling the terminal
var QuitRequested bool         // true if a quit has been issued, but not yet processed. Stops some handlers displaying errors.

//======================================================================

func init() {
	curExpandedStructNodes = make(pdmltree.ExpandedPaths, 0, 20)
	QuitRequestedChan = make(chan struct{}, 1) // buffered because send happens from ui goroutine, which runs global select
	CacheRequestsChan = make(chan struct{}, 1000)
	CacheRequests = make([]pcap.LoadPcapSlice, 0)
	// Buffered because I might send something in this goroutine
	StartUIChan = make(chan struct{}, 1)
	keyState.NumberPrefix = -1 // 0 might be meaningful
	marksMap = make(map[rune]termshark.JumpPos)
	globalMarksMap = make(map[rune]termshark.GlobalJumpPos)
	lastJumpPos = -1

	EnsureTemplateData()
	TemplateData["Marks"] = marksMap
	TemplateData["GlobalMarks"] = globalMarksMap
	TemplateData["Maps"] = getMappings{}
}

type globalJump struct {
	file string
	pos  int
}

type getMappings struct{}

func (g getMappings) Get() []termshark.KeyMapping {
	return termshark.LoadKeyMappings()
}

func (g getMappings) None() bool {
	return len(termshark.LoadKeyMappings()) == 0
}

//======================================================================

type MultiMenuOpener struct {
	under gowid.IWidget
	mm    *MenuHolder
}

var _ menu.IOpener = (*MultiMenuOpener)(nil)

func (o *MultiMenuOpener) OpenMenu(mnu *menu.Widget, site menu.ISite, app gowid.IApp) bool {
	if o.mm.IMenuCompatible != mnu {
		// Adds the menu to the render tree - when not open, under is here instead
		o.mm.IMenuCompatible = mnu
		// Now make under the lower layer of the menu
		mnu.SetSubWidget(o.under, app)
		mnu.OpenImpl(site, app)
		app.Redraw()
		return true
	} else {
		return false
	}
}

func (o *MultiMenuOpener) CloseMenu(mnu *menu.Widget, app gowid.IApp) {
	if o.mm.IMenuCompatible == mnu {
		mnu.CloseImpl(app)
		o.mm.IMenuCompatible = holder.New(o.under)
	}
}

//======================================================================

//
// Handle examples like
// .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
// Extract just
// LG bit
//
// I'm trying to copy what Wireshark does, more or less
//
func columnNameFromShowname(showname string) string {
	matches := shownameRe.FindStringSubmatch(showname)
	if len(matches) >= 3 {
		return matches[2]
	}
	return showname
}

func useAsColumn(filter string, name string, app gowid.IApp) {
	newCols := profiles.ConfStringSlice("main.column-format", []string{})
	colsBak := make([]string, len(newCols))
	for i, col := range newCols {
		colsBak[i] = col
	}

	newCols = append(newCols,
		fmt.Sprintf("%%Cus:%s:0:R", filter),
		columnNameFromShowname(name),
		"true",
	)

	profiles.SetConf("main.column-format-bak", colsBak)
	profiles.SetConf("main.column-format", newCols)

	RequestReload(app)
}

// Build the menu dynamically when needed so I can include the filter in the widgets
func makePdmlFilterMenu(filter string, val string) *menu.Widget {
	sites := make(menuutil.SiteMap)

	needQuotes := false

	ok, field := FieldCompleter.LookupField(filter)
	// should be ok, because this filter comes from the PDML, so the filter should
	// be valid. But if it isn't e.g. newer tshark perhaps, then assume no quotes
	// are needed.
	if ok {
		switch field.Type {
		case fields.FT_STRING:
			needQuotes = true
		case fields.FT_STRINGZ:
			needQuotes = true
		case fields.FT_STRINGZPAD:
			needQuotes = true
		}
	}

	filterStr := filter
	if val != "" {
		if needQuotes {
			filterStr = fmt.Sprintf("%s == \"%s\"", filter, strings.ReplaceAll(val, "\\", "\\\\"))
		} else {
			filterStr = fmt.Sprintf("%s == %s", filter, val)
		}
	}

	var pdmlFilterMenu *menu.Widget

	openPdmlFilterMenu2 := func(prep bool, w gowid.IWidget, app gowid.IApp) {
		st, ok := sites[w]
		if !ok {
			log.Warnf("Unexpected application state: missing menu site for %v", w)
			return
		}

		// This contains logic to close the two PDML menus opened from the struct
		// view and then to either apply or prepare a new display filter based on
		// the one that is currently selected by the user (i.e. the one associated
		// with the open menu)
		actor := &pdmlFilterActor{
			filter:  filterStr,
			prepare: prep,
			menu1:   pdmlFilterMenu,
		}

		menuBox := makeFilterCombineMenuWidget(actor)

		m2 := menu.New("pdmlfilter2", menuBox, fixed, menu.Options{
			Modal:             true,
			CloseKeysProvided: true,
			CloseKeys: []gowid.IKey{
				gowid.MakeKey('q'),
				gowid.MakeKeyExt(tcell.KeyLeft),
				gowid.MakeKeyExt(tcell.KeyEscape),
				gowid.MakeKeyExt(tcell.KeyCtrlC),
			},
		})

		// I need to set this up after constructing m2; m2 itself needs
		// the menu box widget to display; that needs the actor to process
		// the clicks of buttons within that widget, and that actor needs
		// the menu m2 so that it can close it.
		actor.menu2 = m2

		multiMenu2Opener.OpenMenu(m2, st, app)
	}

	pdmlFilterItems := []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Apply as Column: %s", filter),
			Key: gowid.MakeKey('c'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(pdmlFilterMenu, app)
				useAsColumn(curColumnFilter, curColumnFilterName, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Apply Filter: %s", filterStr),
			Key: gowid.MakeKey('a'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				openPdmlFilterMenu2(false, w, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: fmt.Sprintf("Prep Filter: %s", filterStr),
			Key: gowid.MakeKey('p'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				openPdmlFilterMenu2(true, w, app)
			},
		},
	}

	pdmlFilterListBox, pdmlFilterWidth := menuutil.MakeMenuWithHotKeys(pdmlFilterItems, sites)

	// this menu is opened from the PDML struct view and has, as context, the current PDML node. I
	// need a name for it because I use that var in the closure above.
	pdmlFilterMenu = menu.New("pdmlfiltermenu", pdmlFilterListBox, units(pdmlFilterWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	return pdmlFilterMenu
}

//======================================================================

func RequestQuit() {
	select {
	case QuitRequestedChan <- struct{}{}:
	default:
		// Ok for the send not to succeed - there is a buffer of one, and it only
		// needs one message to start the shutdown sequence. So this means a
		// message has already been sent (before the main loop gets round to processing
		// this channel)
	}
}

// Runs in app goroutine
func UpdateProgressBarForInterface(c *pcap.InterfaceLoader, app gowid.IApp) {
	SetProgressIndeterminateFor(app, LoaderOwns)
	loadSpinner.Update()
}

// Runs in app goroutine
func UpdateProgressBarForFile(c *pcap.PacketLoader, prevRatio float64, app gowid.IApp) float64 {
	SetProgressDeterminateFor(app, LoaderOwns)

	psmlProg := Prog{0, 100}
	pdmlPacketProg := Prog{0, 100}
	pdmlIdxProg := Prog{0, 100}
	pcapPacketProg := Prog{0, 100}
	pcapIdxProg := Prog{0, 100}
	curRowProg := Prog{100, 100}

	var err error
	var c2 int64
	var m int64
	var x int

	// This shows where we are in the packet list. We want progress to be active only
	// as long as our view has missing widgets. So this can help predict when our little
	// view into the list of packets will be populated. Note that if a new pcap is loading,
	// the packet list view should always be further away than the last packet, so we won't
	// need the progress bar to tell the user how long until packets appear in the packet
	// list view; but the packet struct and hex views are populated using a different
	// mechanism (separate tshark processes) and may leave their views blank while the
	// packet list view shows data - so the progress bar is useful to indicate when info
	// will show up in the struct and hex views.
	currentDisplayedRow := -1
	var currentDisplayedRowMod int64 = -1
	var currentDisplayedRowDiv int = -1
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			currentRowId, ok := packetListView.Model().RowIdentifier(fxy.Row)
			if ok {
				pktsPerLoad := c.PacketsPerLoad()
				currentDisplayedRow = int(currentRowId)
				currentDisplayedRowMod = int64(currentDisplayedRow % pktsPerLoad)
				// Rounded to 1000 by default
				currentDisplayedRowDiv = (currentDisplayedRow / pktsPerLoad) * pktsPerLoad
				c.PsmlLoader.Lock()
				curRowProg.cur, curRowProg.max = int64(currentDisplayedRow), int64(len(c.PsmlData()))
				c.PsmlLoader.Unlock()
			}
		}
	}

	// Progress determined by how many of the (up to) pktsPerLoad pdml packets are read
	// If it's not the same chunk of rows, assume it won't affect our view, so no progress needed
	if c.PdmlLoader.IsLoading() {
		if c.LoadingRow() == currentDisplayedRowDiv {
			// Data being loaded from pdml + pcap may overlap the current view
			if x, err = c.LengthOfPdmlCacheEntry(c.LoadingRow()); err == nil {
				pdmlPacketProg.cur = int64(x)
				pdmlPacketProg.max = int64(c.KillAfterReadingThisMany)
				if currentDisplayedRow != -1 && currentDisplayedRowMod < pdmlPacketProg.max {
					pdmlPacketProg.max = currentDisplayedRowMod + 1 // zero-based
					if pdmlPacketProg.cur > pdmlPacketProg.max {
						pdmlPacketProg.cur = pdmlPacketProg.max
					}
				}
			}

			// Progress determined by how far through the pcap the pdml reader is.
			c.PdmlLoader.Lock()
			c2, m, err = system.ProcessProgress(c.PdmlPid, c.PcapPdml)
			c.PdmlLoader.Unlock()
			if err == nil {
				pdmlIdxProg.cur, pdmlIdxProg.max = c2, m
				if currentDisplayedRow != -1 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}

			// Progress determined by how many of the (up to) pktsPerLoad pcap packets are read
			if x, err = c.LengthOfPcapCacheEntry(c.LoadingRow()); err == nil {
				pcapPacketProg.cur = int64(x)
				pcapPacketProg.max = int64(c.KillAfterReadingThisMany)
				if currentDisplayedRow != -1 && currentDisplayedRowMod < pcapPacketProg.max {
					pcapPacketProg.max = currentDisplayedRowMod + 1 // zero-based
					if pcapPacketProg.cur > pcapPacketProg.max {
						pcapPacketProg.cur = pcapPacketProg.max
					}
				}
			}

			// Progress determined by how far through the pcap the pcap reader is.
			c.PdmlLoader.Lock()
			c2, m, err = system.ProcessProgress(c.PcapPid, c.PcapPcap)
			c.PdmlLoader.Unlock()
			if err == nil {
				pcapIdxProg.cur, pcapIdxProg.max = c2, m
				if currentDisplayedRow != -1 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}
		}
	}

	if psml, ok := c.PcapPsml.(string); ok && c.PsmlLoader.IsLoading() {
		c.PsmlLoader.Lock()
		c2, m, err = system.ProcessProgress(termshark.SafePid(c.PsmlCmd), psml)
		c.PsmlLoader.Unlock()
		if err == nil {
			psmlProg.cur, psmlProg.max = c2, m
		}
	}

	var prog Prog

	// state is guaranteed not to include pcap.Loadingiface if we showing a determinate progress bar
	switch {
	case c.PsmlLoader.IsLoading() && c.PdmlLoader.IsLoading() && c.PdmlLoader.LoadIsVisible():
		select {
		case <-c.StartStage2ChanFn():
			prog = psmlProg.Add(
				progMax(pcapPacketProg, pcapIdxProg).Add(
					progMax(pdmlPacketProg, pdmlIdxProg),
				),
			)
		default:
			prog = psmlProg.Div(2) // temporarily divide in 2. Leave original for case above - so that the 50%
		}
	case c.PsmlLoader.IsLoading():
		prog = psmlProg
	case c.PdmlLoader.IsLoading() && c.PdmlLoader.LoadIsVisible():
		prog = progMax(pcapPacketProg, pcapIdxProg).Add(
			progMax(pdmlPacketProg, pdmlIdxProg),
		)
	}

	curRatio := float64(prog.cur) / float64(prog.max)

	if prevRatio < curRatio {
		loadProgress.SetTarget(app, int(prog.max))
		loadProgress.SetProgress(app, int(prog.cur))
	}

	return math.Max(prevRatio, curRatio)
}

//======================================================================

// psmlSummary is used to generate a summary for the marks dialog
type psmlSummary []string

func (p psmlSummary) String() string {
	// Skip packet number
	return strings.Join([]string(p)[1:], " : ")
}

//======================================================================

type RenderWeightUpTo struct {
	gowid.RenderWithWeight
	max int
}

func (s RenderWeightUpTo) MaxUnits() int {
	return s.max
}

func weightupto(w int, max int) RenderWeightUpTo {
	return RenderWeightUpTo{gowid.RenderWithWeight{W: w}, max}
}

func units(n int) gowid.RenderWithUnits {
	return gowid.RenderWithUnits{U: n}
}

func weight(n int) gowid.RenderWithWeight {
	return gowid.RenderWithWeight{W: n}
}

func ratio(r float64) gowid.RenderWithRatio {
	return gowid.RenderWithRatio{R: r}
}

type RenderRatioUpTo struct {
	gowid.RenderWithRatio
	max int
}

func (r RenderRatioUpTo) String() string {
	return fmt.Sprintf("upto(%v,%d)", r.RenderWithRatio, r.max)
}

func (r RenderRatioUpTo) MaxUnits() int {
	return r.max
}

func ratioupto(f float64, max int) RenderRatioUpTo {
	return RenderRatioUpTo{gowid.RenderWithRatio{R: f}, max}
}

//======================================================================

// run in app goroutine
func clearPacketViews(app gowid.IApp) {
	packetHexWidgets.Purge()

	packetListViewHolder.SetSubWidget(nullw, app)
	packetStructureViewHolder.SetSubWidget(nullw, app)
	packetHexViewHolder.SetSubWidget(nullw, app)
}

//======================================================================

// Construct decoration around the tree node widget - a button to collapse, etc.
func makeStructNodeDecoration(pos tree.IPos, tr tree.IModel, wmaker tree.IWidgetMaker) gowid.IWidget {
	var res gowid.IWidget
	if tr == nil {
		return nil
	}
	// Note that level should never end up < 0

	// We know our tree widget will never display the root node, so everything will be indented at
	// least one level. So we know this will never end up negative.
	level := -2
	for cur := pos; cur != nil; cur = tree.ParentPosition(cur) {
		level += 1
	}
	if level < 0 {
		panic(errors.WithStack(gowid.WithKVs(termshark.BadState, map[string]interface{}{"level": level})))
	}

	pad := strings.Repeat(" ", level*2)
	cwidgets := make([]gowid.IContainerWidget, 0)
	cwidgets = append(cwidgets,
		&gowid.ContainerWidget{
			IWidget: text.New(pad),
			D:       units(len(pad)),
		},
	)

	ct, ok := tr.(*pdmltree.Model)
	if !ok {
		panic(errors.WithStack(gowid.WithKVs(termshark.BadState, map[string]interface{}{"tree": tr})))
	}

	// Create an empty one here because the selectIf widget needs to have a pointer
	// to it, and it's constructed below as a child.
	rememberSel := &rememberSelected{}

	inner := wmaker.MakeWidget(pos, tr)
	inner = &selectIf{
		IWidget:      inner,
		iWasSelected: rememberSel,
	}

	if ct.HasChildren() {

		var bn *button.Widget
		if ct.IsCollapsed() {
			bn = button.NewAlt(text.New("+"))
		} else {
			bn = button.NewAlt(text.New("-"))
		}

		// If I use one button with conditional logic in the callback, rather than make
		// a separate button depending on whether or not the tree is collapsed, it will
		// correctly work when the DecoratorMaker is caching the widgets i.e. it will
		// collapse or expand even when the widget is rendered from the cache
		bn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
			// Run this outside current event loop because we are implicitly
			// adjusting the data structure behind the list walker, and it's
			// not prepared to handle that in the same pass of processing
			// UserInput. TODO.
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				ct.SetCollapsed(app, !ct.IsCollapsed())
			}))
		}))

		expandContractKeys := appkeys.New(
			bn,
			func(ev *tcell.EventKey, app gowid.IApp) bool {
				handled := false
				switch ev.Key() {
				case tcell.KeyLeft:
					if !ct.IsCollapsed() {
						ct.SetCollapsed(app, true)
						handled = true
					}
				case tcell.KeyRight:
					if ct.IsCollapsed() {
						ct.SetCollapsed(app, false)
						handled = true
					}
				}
				return handled
			},
		)

		cwidgets = append(cwidgets,
			&gowid.ContainerWidget{
				IWidget: expandContractKeys,
				D:       fixed,
			},
			&gowid.ContainerWidget{
				IWidget: fillSpace,
				D:       units(1),
			},
		)
	} else {
		// Lines without an expander are just text - so you can't cursor down on to them unless you
		// make them selectable (because the list will jump over them)
		inner = selectable.New(inner)

		cwidgets = append(cwidgets,
			&gowid.ContainerWidget{
				IWidget: fillSpace,
				D:       units(4),
			},
		)

	}

	cwidgets = append(cwidgets, &gowid.ContainerWidget{
		IWidget: inner,
		D:       weight(1),
	})

	res = columns.New(cwidgets)

	rememberSel.IWidget = res

	res = expander.New(
		isselected.New(
			rememberSel,
			styled.New(rememberSel, gowid.MakePaletteRef("packet-struct-selected")),
			styled.New(rememberSel, gowid.MakePaletteRef("packet-struct-focus")),
		),
	)

	return res
}

// rememberSelected, when rendered, will save whether or not the selected flag was set.
// Another widget (deeper in the hierarchy) can then consult it to see whether it should
// render differently as the grandchild of a selected widget.
type rememberSelected struct {
	gowid.IWidget
	selectedThisTime bool
}

type iWasSelected interface {
	WasSelected() bool
}

func (w *rememberSelected) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	w.selectedThisTime = focus.Selected
	return w.IWidget.Render(size, focus, app)
}

func (w *rememberSelected) WasSelected() bool {
	return w.selectedThisTime
}

// selectIf sets the selected flag on its child if its iWasSelected type returns true
type selectIf struct {
	gowid.IWidget
	iWasSelected
}

func (w *selectIf) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if w.iWasSelected.WasSelected() {
		focus = focus.SelectIf(true)
	}
	return w.IWidget.Render(size, focus, app)
}

// The widget representing the data at this level in the tree. Simply use what we extract from
// the PDML.
func makeStructNodeWidget(pos tree.IPos, tr tree.IModel) gowid.IWidget {
	pdmlMenuButton := button.NewBare(text.New("[=]"))
	pdmlMenuButtonSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	pdmlMenuButton.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		curColumnFilter = tr.(*pdmltree.Model).Name
		curColumnFilterValue = tr.(*pdmltree.Model).Show
		curColumnFilterName = tr.(*pdmltree.Model).UiName
		pdmlFilterMenu := makePdmlFilterMenu(curColumnFilter, curColumnFilterValue)
		multiMenu1Opener.OpenMenu(pdmlFilterMenu, pdmlMenuButtonSite, app)
	}))

	styledButton1 := styled.New(pdmlMenuButton, gowid.MakePaletteRef("packet-struct-selected"))
	styledButton2 := styled.New(
		pdmlMenuButton,
		gowid.MakeStyledAs(gowid.StyleBold),
	)

	structText := text.New(tr.Leaf())

	structIfNotSel := columns.NewFixed(structText)
	structIfSel := columns.NewFixed(structText, colSpace, pdmlMenuButtonSite, styledButton1)
	structIfFocus := columns.NewFixed(structText, colSpace, pdmlMenuButtonSite, styledButton2)

	return selectable.New(isselected.New(structIfNotSel, structIfSel, structIfFocus))
}

//======================================================================

// I want to have preferred position work on this, but you have to choose a subwidget
// to navigate to. We have three. I know that my use of them is very similar, so I'll
// just pick the first
type selectedComposite struct {
	*isselected.Widget
}

var _ gowid.IComposite = (*selectedComposite)(nil)

func (w *selectedComposite) SubWidget() gowid.IWidget {
	return w.Not
}

//======================================================================

// An ugly interface that captures what sort of type will be suitable
// as a table widget to which a row focus can be applied.
type iRowFocusTableWidgetNeeds interface {
	gowid.IWidget
	list.IBoundedWalker
	table.IFocus
	table.IGoToMiddle
	table.ISetFocus
	list.IWalkerHome
	list.IWalkerEnd
	SetPos(pos list.IBoundedWalkerPosition, app gowid.IApp)
	FocusXY() (table.Coords, error)
	SetFocusXY(gowid.IApp, table.Coords)
	SetModel(table.IModel, gowid.IApp)
	Lower() *table.ListWithPreferedColumn
	SetFocusOnData(app gowid.IApp) bool
	OnFocusChanged(f gowid.IWidgetChangedCallback)
}

// rowFocusTableWidget provides a table that highlights the selected row or
// focused row.
type rowFocusTableWidget struct {
	iRowFocusTableWidgetNeeds
	rowSelected string
	rowFocus    string
}

func NewRowFocusTableWidget(w iRowFocusTableWidgetNeeds, rs string, rf string) *rowFocusTableWidget {
	res := &rowFocusTableWidget{
		iRowFocusTableWidgetNeeds: w,
		rowSelected:               rs,
		rowFocus:                  rf,
	}
	res.Lower().IWidget = list.NewBounded(res)
	return res
}

var _ gowid.IWidget = (*rowFocusTableWidget)(nil)

func (t *rowFocusTableWidget) SubWidget() gowid.IWidget {
	return t.iRowFocusTableWidgetNeeds
}

func (t *rowFocusTableWidget) InvertedModel() table.IInvertible {
	return t.Model().(table.IInvertible)
}

func (t *rowFocusTableWidget) Rows() int {
	return t.Model().(table.IBoundedModel).Rows()
}

// Implement withscrollbar.IScrollValues
func (t *rowFocusTableWidget) ScrollLength() int {
	return t.Rows()
}

// Implement withscrollbar.IScrollValues
func (t *rowFocusTableWidget) ScrollPosition() int {
	return t.CurrentRow()
}

func (t *rowFocusTableWidget) Up(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) Down(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyDown, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) UpPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyPgUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		t.UserInput(tcell.NewEventKey(tcell.KeyPgDn, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

// list.IWalker
func (t *rowFocusTableWidget) At(lpos list.IWalkerPosition) gowid.IWidget {
	pos := int(lpos.(table.Position))
	w := t.AtRow(pos)
	if w == nil {
		return nil
	}

	// Composite so it passes through preferred column
	var res gowid.IWidget = &selectedComposite{
		Widget: isselected.New(w,
			styled.New(w, gowid.MakePaletteRef(t.rowSelected)),
			styled.New(w, gowid.MakePaletteRef(t.rowFocus)),
		),
	}

	return res
}

// Needed for WidgetAt above to work - otherwise t.Table.Focus() is called, table is the receiver,
// then it calls WidgetAt so ours is not used.
func (t *rowFocusTableWidget) Focus() list.IWalkerPosition {
	return table.Focus(t)
}

//======================================================================

// A rowFocusTableWidget that adds colors to rows
type psmlTableRowWidget struct {
	*rowFocusTableWidget
	// set to true after the first time we move focus from the table header to the data. We do this
	// once and that this happens quickly, but then assume the user might want to move back to the
	// table header manually, and it would be strange if the table keeps jumping back to the data...
	didFirstAutoFocus bool
	colors            []pcap.PacketColors
}

func NewPsmlTableRowWidget(w *rowFocusTableWidget, c []pcap.PacketColors) *psmlTableRowWidget {
	res := &psmlTableRowWidget{
		rowFocusTableWidget: w,
		colors:              c,
	}
	res.Lower().IWidget = list.NewBounded(res)
	return res
}

func (t *psmlTableRowWidget) At(lpos list.IWalkerPosition) gowid.IWidget {
	res := t.rowFocusTableWidget.At(lpos)
	if res == nil {
		return nil
	}
	pos := int(lpos.(table.Position))

	// Check the color array length because it might not yet be adequately
	// populated from the arriving psml.
	if pos >= 0 && PacketColors && pos < len(t.colors) {
		res = styled.New(res,
			gowid.MakePaletteEntry(t.colors[pos].FG, t.colors[pos].BG),
		)
	}

	return res
}

func (t *psmlTableRowWidget) Focus() list.IWalkerPosition {
	return table.Focus(t)
}

//======================================================================

type pleaseWaitCallbacks struct {
	w    *spinner.Widget
	app  gowid.IApp
	open bool
}

func (s *pleaseWaitCallbacks) ProcessWaitTick() error {
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		s.w.Update()
		if !s.open {
			OpenPleaseWait(appView, s.app)
			s.open = true
		}
	}))
	return nil
}

// Call in app context
func (s *pleaseWaitCallbacks) closeWaitDialog(app gowid.IApp) {
	if s.open {
		ClosePleaseWait(app)
		s.open = false
	}
}

func (s *pleaseWaitCallbacks) ProcessCommandDone() {
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		s.closeWaitDialog(app)
	}))
}

//======================================================================

// Wait until the copy command has finished, then open up a dialog with the results.
type urlCopiedCallbacks struct {
	app      gowid.IApp
	tmplName string
	*pleaseWaitCallbacks
}

var (
	_ termshark.ICommandOutput     = urlCopiedCallbacks{}
	_ termshark.ICommandError      = urlCopiedCallbacks{}
	_ termshark.ICommandDone       = urlCopiedCallbacks{}
	_ termshark.ICommandKillError  = urlCopiedCallbacks{}
	_ termshark.ICommandTimeout    = urlCopiedCallbacks{}
	_ termshark.ICommandWaitTicker = urlCopiedCallbacks{}
)

func (h urlCopiedCallbacks) displayDialog(output string) {
	TemplateData["CopyCommandMessage"] = output

	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenTemplatedDialog(appView, h.tmplName, app)
		delete(TemplateData, "CopyCommandMessage")
	}))
}

func (h urlCopiedCallbacks) ProcessOutput(output string) error {
	var msg string
	if len(output) == 0 {
		msg = "URL copied to clipboard."
	} else {
		msg = output
	}
	h.displayDialog(msg)
	return nil
}

func (h urlCopiedCallbacks) ProcessCommandTimeout() error {
	h.displayDialog("")
	return nil
}

func (h urlCopiedCallbacks) ProcessCommandError(err error) error {
	h.displayDialog("")
	return nil
}

func (h urlCopiedCallbacks) ProcessKillError(err error) error {
	h.displayDialog("")
	return nil
}

//======================================================================

type userCopiedCallbacks struct {
	app     gowid.IApp
	copyCmd []string
	*pleaseWaitCallbacks
}

var (
	_ termshark.ICommandOutput     = userCopiedCallbacks{}
	_ termshark.ICommandError      = userCopiedCallbacks{}
	_ termshark.ICommandDone       = userCopiedCallbacks{}
	_ termshark.ICommandKillError  = userCopiedCallbacks{}
	_ termshark.ICommandTimeout    = userCopiedCallbacks{}
	_ termshark.ICommandWaitTicker = userCopiedCallbacks{}
)

func (h userCopiedCallbacks) ProcessCommandTimeout() error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Copy command \"%v\" timed out", strings.Join(h.copyCmd, " ")), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessCommandError(err error) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Copy command \"%v\" failed: %v", strings.Join(h.copyCmd, " "), err), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessKillError(err error) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		OpenError(fmt.Sprintf("Timed out, but could not kill copy command: %v", err), app)
	}))
	return nil
}

func (h userCopiedCallbacks) ProcessOutput(output string) error {
	h.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		h.closeWaitDialog(app)
		if len(output) == 0 {
			OpenMessage("   Copied!   ", appView, app)
		} else {
			OpenMessage(fmt.Sprintf("Copied! Output was:\n%s\n", output), appView, app)
		}
	}))
	return nil
}

//======================================================================

type OpenErrorDialog struct{}

func (f OpenErrorDialog) OnError(err error, app gowid.IApp) {
	OpenError(err.Error(), app)
}

func OpenError(msgt string, app gowid.IApp) *dialog.Widget {
	// the same, for now
	return OpenMessage(msgt, appView, app)
}

func OpenLongError(msgt string, app gowid.IApp) *dialog.Widget {
	// the same, for now
	return OpenLongMessage(msgt, appView, app)
}

func openResultsAfterCopy(tmplName string, tocopy string, app gowid.IApp) {
	v := urlCopiedCallbacks{
		app:      app,
		tmplName: tmplName,
		pleaseWaitCallbacks: &pleaseWaitCallbacks{
			w:   pleaseWaitSpinner,
			app: app,
		},
	}
	termshark.CopyCommand(strings.NewReader(tocopy), v)
}

func processCopyChoices(copyLen int, app gowid.IApp) {
	var cc *dialog.Widget

	copyCmd := profiles.ConfStringSlice(
		"main.copy-command",
		system.CopyToClipboard,
	)

	if len(copyCmd) == 0 {
		OpenError("Config file has an invalid copy-command entry! Please remove it.", app)
		return
	}

	clips := app.Clips()

	// No need to display a choice dialog with one choice - just copy right away
	if len(clips) == 1 {
		app.InCopyMode(false)
		termshark.CopyCommand(strings.NewReader(clips[0].ClipValue()), userCopiedCallbacks{
			app:     app,
			copyCmd: copyCmd,
			pleaseWaitCallbacks: &pleaseWaitCallbacks{
				w:   pleaseWaitSpinner,
				app: app,
			},
		})
		return
	}

	cws := make([]gowid.IWidget, 0, len(clips))

	for _, clip := range clips {
		c2 := clip
		lbl := text.New(clip.ClipName() + ":")
		btxt1 := clip.ClipValue()
		if copyLen > 0 {
			blines := strings.Split(btxt1, "\n")
			if len(blines) > copyLen {
				blines[copyLen-1] = "..."
				blines = blines[0:copyLen]
			}
			btxt1 = strings.Join(blines, "\n")
		}

		btn := button.NewBare(text.New(btxt1, text.Options{
			Wrap:          text.WrapClip,
			ClipIndicator: "...",
		}))

		btn.OnClick(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			cc.Close(app)
			app.InCopyMode(false)

			termshark.CopyCommand(strings.NewReader(c2.ClipValue()), userCopiedCallbacks{
				app:     app,
				copyCmd: copyCmd,
				pleaseWaitCallbacks: &pleaseWaitCallbacks{
					w:   pleaseWaitSpinner,
					app: app,
				},
			})
		})))

		btn2 := styled.NewFocus(btn, gowid.MakeStyledAs(gowid.StyleReverse))
		tog := pile.NewFlow(lbl, btn2, divider.NewUnicode())
		cws = append(cws, tog)
	}

	walker := list.NewSimpleListWalker(cws)
	clipList := list.New(walker)

	// Do this so the list box scrolls inside the dialog
	view2 := &gowid.ContainerWidget{
		IWidget: clipList,
		D:       weight(1),
	}

	var view1 gowid.IWidget = pile.NewFlow(text.New("Select option to copy:"), divider.NewUnicode(), view2)

	cc = dialog.New(view1,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			FocusOnWidget:   true,
		},
	)

	cc.OnOpenClose(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
		if !cc.IsOpen() {
			app.InCopyMode(false)
		}
	})))

	dialog.OpenExt(cc, appView, ratio(0.5), ratio(0.8), app)
}

type callWithAppFn func(gowid.IApp)

func askToSave(app gowid.IApp, next callWithAppFn) {
	msgt := fmt.Sprintf("Current capture saved to %s", Loader.InterfaceFile())
	msg := text.New(msgt)
	var keepPackets *dialog.Widget
	keepPackets = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Keep",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							keepPackets.Close(app)
							next(app)
						},
					),
				},
				dialog.Button{
					Msg: "Delete",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							WriteToDeleted = true
							err := os.Remove(Loader.InterfaceFile())
							if err != nil {
								log.Errorf("Could not delete file %s: %v", Loader.InterfaceFile(), err)
							}
							keepPackets.Close(app)
							next(app)
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)
	keepPackets.Open(appView, units(len(msgt)+20), app)
}

func reallyQuit(app gowid.IApp) {
	msgt := "Do you want to quit?"
	msg := text.New(msgt)
	YesNo = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, widget gowid.IWidget) {
							YesNo.Close(app)
							// (a) Loader is in interface mode (b) User did not set -w flag
							// (c) always-keep-pcap setting is unset (def false) or false
							if Loader.InterfaceFile() != "" && !WriteToSelected &&
								!profiles.ConfBool("main.always-keep-pcap", false) {
								askToSave(app, func(app gowid.IApp) {
									RequestQuit()
								})
							} else {
								RequestQuit()
							}
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
		},
	)
	YesNo.Open(appView, units(len(msgt)+20), app)
}

func lastLineMode(app gowid.IApp) {
	MiniBuffer = minibuffer.New()

	MiniBuffer.Register("quit", minibufferFn(func(gowid.IApp, ...string) error {
		reallyQuit(app)
		return nil
	}))

	// force quit
	MiniBuffer.Register("q!", quietMinibufferFn(func(gowid.IApp, ...string) error {
		RequestQuit()
		return nil
	}))

	MiniBuffer.Register("no-theme", minibufferFn(func(app gowid.IApp, s ...string) error {
		mode := theme.Mode(app.GetColorMode()).String() // more concise
		profiles.DeleteConf(fmt.Sprintf("main.theme-%s", mode))
		ApplyCurrentTheme(app)
		SetupColors()
		var prof string
		if profiles.Current() != profiles.Default() {
			prof = fmt.Sprintf("in profile %s ", profiles.CurrentName())
		}
		OpenMessage(fmt.Sprintf("Cleared theme %sfor terminal mode %v.", prof, app.GetColorMode()), appView, app)
		return nil
	}))

	MiniBuffer.Register("convs", minibufferFn(func(gowid.IApp, ...string) error {
		openConvsUi(app)
		return nil
	}))

	MiniBuffer.Register("streams", minibufferFn(func(gowid.IApp, ...string) error {
		startStreamReassembly(app)
		return nil
	}))

	MiniBuffer.Register("capinfo", minibufferFn(func(gowid.IApp, ...string) error {
		startCapinfo(app)
		return nil
	}))

	MiniBuffer.Register("columns", minibufferFn(func(gowid.IApp, ...string) error {
		openEditColumns(app)
		return nil
	}))

	MiniBuffer.Register("wormhole", minibufferFn(func(gowid.IApp, ...string) error {
		openWormhole(app)
		return nil
	}))

	MiniBuffer.Register("menu", minibufferFn(func(gowid.IApp, ...string) error {
		openGeneralMenu(app)
		return nil
	}))

	MiniBuffer.Register("clear-packets", minibufferFn(func(gowid.IApp, ...string) error {
		reallyClear(app)
		return nil
	}))

	MiniBuffer.Register("clear-filter", minibufferFn(func(gowid.IApp, ...string) error {
		FilterWidget.SetValue("", app)
		RequestNewFilter(FilterWidget.Value(), app)
		return nil
	}))

	MiniBuffer.Register("marks", minibufferFn(func(gowid.IApp, ...string) error {
		OpenTemplatedDialogExt(appView, "Marks", fixed, ratio(0.6), app)
		return nil
	}))

	if runtime.GOOS != "windows" {
		MiniBuffer.Register("logs", minibufferFn(func(gowid.IApp, ...string) error {
			openLogsUi(app)
			return nil
		}))
		MiniBuffer.Register("config", minibufferFn(func(gowid.IApp, ...string) error {
			openConfigUi(app)
			return nil
		}))
	}

	MiniBuffer.Register("set", setCommand{})

	// read new pcap
	MiniBuffer.Register("r", readCommand{complete: false})
	MiniBuffer.Register("e", readCommand{complete: false})
	MiniBuffer.Register("load", readCommand{complete: true})
	MiniBuffer.Register("recents", recentsCommand{})
	MiniBuffer.Register("filter", filterCommand{})
	MiniBuffer.Register("theme", themeCommand{})
	MiniBuffer.Register("profile", newProfileCommand())
	MiniBuffer.Register("map", mapCommand{w: keyMapper})
	MiniBuffer.Register("unmap", unmapCommand{w: keyMapper})
	MiniBuffer.Register("help", helpCommand{})

	minibuffer.Open(MiniBuffer, mbView, ratio(1.0), app)
}

//======================================================================

func getCurrentStructModel(row int) *pdmltree.Model {
	return getCurrentStructModelWith(row, Loader.PsmlLoader)
}

// getCurrentStructModelWith will return a termshark model of a packet section of PDML given a row number,
// or nil if there is no model for the given row.
func getCurrentStructModelWith(row int, lock sync.Locker) *pdmltree.Model {
	var res *pdmltree.Model

	pktsPerLoad := Loader.PacketsPerLoad()
	row2 := (row / pktsPerLoad) * pktsPerLoad

	lock.Lock()
	defer lock.Unlock()
	if ws, ok := Loader.PacketCache.Get(row2); ok {
		srca := ws.(pcap.CacheEntry).Pdml
		if len(srca) > row%pktsPerLoad {
			data, err := xml.Marshal(srca[row%pktsPerLoad].Packet())
			if err != nil {
				log.Fatal(err)
			}

			res = pdmltree.DecodePacket(data)
		}
	}

	return res
}

//======================================================================

func reallyClear(app gowid.IApp) {
	confirmAction(
		"Do you want to clear current capture?",
		func(app gowid.IApp) {
			Loader.ClearPcap(
				pcap.HandlerList{
					SimpleErrors{},
					MakePacketViewUpdater(),
					MakeUpdateCurrentCaptureInTitle(),
					ManageStreamCache{},
					ManageCapinfoCache{},
					SetStructWidgets{Loader}, // for OnClear
					ClearMarksHandler{},
					ManageSearchData{},
					CancelledMessage{},
				},
			)
		},
		app,
	)
}

func confirmAction(msgt string, ok func(gowid.IApp), app gowid.IApp) {
	msg := text.New(msgt)
	YesNo = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: gowid.MakeWidgetCallback("cb",
						func(app gowid.IApp, w gowid.IWidget) {
							YesNo.Close(app)
							ok(app)
						},
					),
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)
	YesNo.Open(mainViewNoKeys, units(len(msgt)+28), app)
}

//======================================================================

func appKeysResize1(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		mainviewRows.AdjustOffset(2, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRows.AdjustOffset(2, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func appKeysResize2(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		mainviewRows.AdjustOffset(4, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRows.AdjustOffset(4, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview1ColsKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '>' {
		altview1Cols.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '<' {
		altview1Cols.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview1PileKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		altview1Pile.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		altview1Pile.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview2ColsKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '>' {
		altview2Cols.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '<' {
		altview2Cols.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func altview2PileKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		altview2Pile.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		altview2Pile.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func copyModeExitKeys(evk *tcell.EventKey, app gowid.IApp) bool {
	return copyModeExitKeysClipped(evk, 0, app)
}

// Used for limiting samples of reassembled streams
func copyModeExitKeys20(evk *tcell.EventKey, app gowid.IApp) bool {
	return copyModeExitKeysClipped(evk, 20, app)
}

func copyModeExitKeysClipped(evk *tcell.EventKey, copyLen int, app gowid.IApp) bool {
	handled := false
	if app.InCopyMode() {
		handled = true

		switch evk.Key() {
		case tcell.KeyRune:
			switch evk.Rune() {
			case 'q', 'c':
				app.InCopyMode(false)
			case '?':
				OpenTemplatedDialog(appView, "CopyModeHelp", app)
			}
		case tcell.KeyEscape:
			app.InCopyMode(false)
		case tcell.KeyCtrlC:
			processCopyChoices(copyLen, app)
		case tcell.KeyRight:
			cl := app.CopyModeClaimedAt()
			app.CopyModeClaimedAt(cl + 1)
			app.RefreshCopyMode()
		case tcell.KeyLeft:
			cl := app.CopyModeClaimedAt()
			if cl > 0 {
				app.CopyModeClaimedAt(cl - 1)
				app.RefreshCopyMode()
			}
		}
	}
	return handled
}

func copyModeEnterKeys(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	if !app.InCopyMode() {
		switch evk.Key() {
		case tcell.KeyRune:
			switch evk.Rune() {
			case 'c':
				app.InCopyMode(true)
				handled = true
			}
		}
	}
	return handled
}

func setFocusOnPacketList(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[0], app)
	gowid.SetFocusPath(altview1, altview1Paths[0], app)
	gowid.SetFocusPath(altview2, altview2Paths[0], app)
	gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
}

func setFocusOnPacketStruct(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[1], app)
	gowid.SetFocusPath(altview1, altview1Paths[1], app)
	gowid.SetFocusPath(altview2, altview2Paths[1], app)
	gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
}

func setFocusOnPacketHex(app gowid.IApp) {
	gowid.SetFocusPath(mainview, mainviewPaths[2], app)
	gowid.SetFocusPath(altview1, altview1Paths[2], app)
	gowid.SetFocusPath(altview2, altview2Paths[2], app)
	gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)
}

func setFocusOnDisplayFilter(app gowid.IApp) {
	gowid.SetFocusPath(mainview, filterPathMain, app)
	gowid.SetFocusPath(altview1, filterPathAlt, app)
	gowid.SetFocusPath(altview2, filterPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, filterPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, filterPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, filterPathMax, app)
}

func setFocusOnSearch(app gowid.IApp) {
	gowid.SetFocusPath(mainview, searchPathMain, app)
	gowid.SetFocusPath(altview1, searchPathAlt, app)
	gowid.SetFocusPath(altview2, searchPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, searchPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, searchPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, searchPathMax, app)
}

func clearOffsets(app gowid.IApp) {
	if mainViewNoKeys.SubWidget() == mainview {
		mainviewRows.SetOffsets([]resizable.Offset{}, app)
	} else if mainViewNoKeys.SubWidget() == altview1 {
		altview1Cols.SetOffsets([]resizable.Offset{}, app)
		altview1Pile.SetOffsets([]resizable.Offset{}, app)
	} else {
		altview2Cols.SetOffsets([]resizable.Offset{}, app)
		altview2Pile.SetOffsets([]resizable.Offset{}, app)
	}
}

func packetNumberFromCurrentTableRow() (termshark.JumpPos, error) {
	tablePos, err := packetListView.FocusXY() // e.g. table position 5
	if err != nil {
		return termshark.JumpPos{}, fmt.Errorf("No packet in focus: %v", err)
	}
	return packetNumberFromTableRow(tablePos.Row)
}

func tableRowFromPacketNumber(savedPacket int) (int, error) {
	// Map e.g. packet number #123 to the index in the PSML array - e.g. index 10 (order of psml load)
	packetRowId, ok := Loader.PacketNumberMap[savedPacket]
	if !ok {
		return -1, fmt.Errorf("Error finding packet %v", savedPacket)
	}
	// This psml order is also the table RowId order. The table might be sorted though, so
	// map this RowId to the actual table row, so we can change focus to it
	tableRow, ok := packetListView.InvertedModel().IdentifierToRow(table.RowId(packetRowId))
	if !ok {
		return -1, fmt.Errorf("Error looking up packet %v", packetRowId)
	}

	return tableRow, nil
}

func packetNumberFromTableRow(tableRow int) (termshark.JumpPos, error) {
	packetRowId, ok := packetListView.Model().RowIdentifier(tableRow)
	if !ok {
		return termshark.JumpPos{}, fmt.Errorf("Error looking up packet at row %v", tableRow)
	}

	// e.g. packet #123

	var summary string
	if len(Loader.PsmlData()) > int(packetRowId) {
		summary = psmlSummary(Loader.PsmlData()[packetRowId]).String()
	}

	if int(packetRowId) >= len(Loader.PsmlData()) {
		return termshark.JumpPos{}, fmt.Errorf("Packet %d is not loaded.", packetRowId)
	}

	packetNum, err := strconv.Atoi(Loader.PsmlData()[packetRowId][0])
	if err != nil {
		return termshark.JumpPos{}, fmt.Errorf("Unexpected error determining no. of packet %d: %v.", tableRow, err)
	}

	return termshark.JumpPos{
		Pos:     packetNum,
		Summary: summary,
	}, nil
}

func searchOpen() bool {
	return filterHolder.SubWidget() == filterWithSearch
}

func searchIsActive() bool {
	return stopCurrentSearch != nil
}

func searchPacketsMainView(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	if evk.Key() == tcell.KeyCtrlF {
		if !searchOpen() {
			filterHolder.SetSubWidget(filterWithSearch, app)
			setFocusOnSearch(app)
		} else {
			// If it's open and focus is on the text area for search, then close it
			if SearchWidget != nil && SearchWidget.FocusIsOnFilter() {
				filterHolder.SetSubWidget(filterWithoutSearch, app)
				// This seems to make the most sense
				setFocusOnPacketList(app)
			} else {
				// Otherwise, put focus on the text area. This provides for a quick
				// way to get control back on the search text area - ctrl-f will do it.
				// Closing search is then just two ctrl-f keypresses at most.
				setFocusOnSearch(app)
			}
		}
	} else {
		handled = false
	}

	return handled
}

// These only apply to the traditional wireshark-like main view
func vimKeysMainView(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	if evk.Key() == tcell.KeyCtrlW && keyState.PartialCtrlWCmd {
		cycleView(app, true, tabViewsForward)
	} else if evk.Key() == tcell.KeyRune && evk.Rune() == '=' && keyState.PartialCtrlWCmd {
		clearOffsets(app)
	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'a' && evk.Rune() <= 'z' && keyState.PartialmCmd {
		if packetListView != nil {
			tablePos, err := packetListView.FocusXY() // e.g. table position 5
			if err != nil {
				OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
			} else {
				jpos, err := packetNumberFromTableRow(tablePos.Row)
				if err != nil {
					OpenError(err.Error(), app)
				} else {
					marksMap[evk.Rune()] = jpos
					OpenMessage(fmt.Sprintf("Local mark '%c' set to packet %v.", evk.Rune(), jpos.Pos), appView, app)
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'A' && evk.Rune() <= 'Z' && keyState.PartialmCmd {

		if Loader != nil {
			if Loader.Pcap() != "" {
				if packetListView != nil {
					tablePos, err := packetListView.FocusXY()
					if err != nil {
						OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
					} else {
						jpos, err := packetNumberFromTableRow(tablePos.Row)
						if err != nil {
							OpenError(err.Error(), app)
						} else {
							globalMarksMap[evk.Rune()] = termshark.GlobalJumpPos{
								JumpPos:  jpos,
								Filename: Loader.Pcap(),
							}
							termshark.SaveGlobalMarks(globalMarksMap)
							OpenMessage(fmt.Sprintf("Global mark '%c' set to packet %v.", evk.Rune(), jpos.Pos), appView, app)
						}
					}
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'a' && evk.Rune() <= 'z' && keyState.PartialQuoteCmd {
		if packetListView != nil {
			markedPacket, ok := marksMap[evk.Rune()]
			if ok {
				tableRow, err := tableRowFromPacketNumber(markedPacket.Pos)
				if err != nil {
					OpenError(err.Error(), app)
				} else {

					tableCol := 0
					curTablePos, err := packetListView.FocusXY()
					if err == nil {
						tableCol = curTablePos.Column
					}

					pn, _ := packetNumberFromCurrentTableRow() // save for ''
					lastJumpPos = pn.Pos

					packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() >= 'A' && evk.Rune() <= 'Z' && keyState.PartialQuoteCmd {
		markedPacket, ok := globalMarksMap[evk.Rune()]
		if !ok {
			OpenError("Mark not found.", app)
		} else {
			if Loader.Pcap() != markedPacket.Filename {
				MaybeKeepThenRequestLoadPcap(markedPacket.Filename, FilterWidget.Value(), markedPacket, app)
			} else {

				if packetListView != nil {
					tableRow, err := tableRowFromPacketNumber(markedPacket.Pos)
					if err != nil {
						OpenError(err.Error(), app)
					} else {

						tableCol := 0
						curTablePos, err := packetListView.FocusXY()
						if err == nil {
							tableCol = curTablePos.Column
						}

						pn, _ := packetNumberFromCurrentTableRow() // save for ''
						lastJumpPos = pn.Pos

						packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
					}
				}
			}
		}

	} else if evk.Key() == tcell.KeyRune && evk.Rune() == '\'' && keyState.PartialQuoteCmd {
		if packetListView != nil {
			tablePos, err := packetListView.FocusXY()
			if err != nil {
				OpenError(fmt.Sprintf("No packet in focus: %v", err), app)
			} else {
				// which packet number was saved as a mark
				savedPacket := lastJumpPos
				if savedPacket != -1 {
					// Map that packet number #123 to the index in the PSML array - e.g. index 10 (order of psml load)
					if packetRowId, ok := Loader.PacketNumberMap[savedPacket]; !ok {
						OpenError(fmt.Sprintf("Error finding packet %v", savedPacket), app)
					} else {
						// This psml order is also the table RowId order. The table might be sorted though, so
						// map this RowId to the actual table row, so we can change focus to it
						if tableRow, ok := packetListView.InvertedModel().IdentifierToRow(table.RowId(packetRowId)); !ok {
							OpenError(fmt.Sprintf("Error looking up packet %v", packetRowId), app)
						} else {
							pn, _ := packetNumberFromCurrentTableRow() // save for ''
							lastJumpPos = pn.Pos

							packetListView.SetFocusXY(app, table.Coords{Column: tablePos.Column, Row: tableRow})
						}
					}
				}
			}
		}

	} else {
		handled = false
	}

	return handled
}

func currentlyFocusedViewNotHex() bool {
	return currentlyFocusedViewNotByIndex(2)
}

func currentlyFocusedViewNotStruct() bool {
	return currentlyFocusedViewNotByIndex(1)
}

func currentlyFocusedViewNotByIndex(idx int) bool {
	if mainViewNoKeys.SubWidget() == mainview {
		v1p := gowid.FocusPath(mainview)
		if deep.Equal(v1p, mainviewPaths[idx]) != nil { // it's not hex
			return true
		}
	} else if mainViewNoKeys.SubWidget() == altview1 {
		v2p := gowid.FocusPath(altview1)
		if deep.Equal(v2p, altview1Paths[idx]) != nil { // it's not hex
			return true
		}
	} else { // altview2
		v3p := gowid.FocusPath(altview2)
		if deep.Equal(v3p, altview2Paths[idx]) != nil { // it's not hex
			return true
		}
	}
	return false
}

// Move focus among the packet list view, structure view and hex view
func cycleView(app gowid.IApp, forward bool, tabMap map[gowid.IWidget]gowid.IWidget) {
	if v, ok := tabMap[mainViewNoKeys.SubWidget()]; ok {
		mainViewNoKeys.SetSubWidget(v, app)
	}

	gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
	gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)

	if packetStructureViewHolder.SubWidget() == MissingMsgw {
		setFocusOnPacketList(app)
	} else {
		newidx := -1
		if mainViewNoKeys.SubWidget() == mainview {
			v1p := gowid.FocusPath(mainview)
			if deep.Equal(v1p, mainviewPaths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v1p, mainviewPaths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		} else if mainViewNoKeys.SubWidget() == altview1 {
			v2p := gowid.FocusPath(altview1)
			if deep.Equal(v2p, altview1Paths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v2p, altview1Paths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		} else if mainViewNoKeys.SubWidget() == altview2 {
			v3p := gowid.FocusPath(altview2)
			if deep.Equal(v3p, altview2Paths[0]) == nil {
				newidx = gwutil.If(forward, 1, 2).(int)
			} else if deep.Equal(v3p, altview2Paths[1]) == nil {
				newidx = gwutil.If(forward, 2, 0).(int)
			} else {
				newidx = gwutil.If(forward, 0, 1).(int)
			}
		}

		if newidx != -1 {
			// Keep the views in sync
			gowid.SetFocusPath(mainview, mainviewPaths[newidx], app)
			gowid.SetFocusPath(altview1, altview1Paths[newidx], app)
			gowid.SetFocusPath(altview2, altview2Paths[newidx], app)
		}
	}
}

// Keys for the main view - packet list, structure, etc
func mainKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true

	isrune := evk.Key() == tcell.KeyRune

	if evk.Key() == tcell.KeyCtrlC && searchIsActive() {
		stopCurrentSearch.RequestStop(app)
	} else if evk.Key() == tcell.KeyCtrlC && Loader.PsmlLoader.IsLoading() {
		Loader.StopLoadPsmlAndIface(NoHandlers{}) // iface and psml
	} else if evk.Key() == tcell.KeyTAB || evk.Key() == tcell.KeyBacktab {
		isTab := (evk.Key() == tcell.KeyTab)
		var tabMap map[gowid.IWidget]gowid.IWidget
		if isTab {
			tabMap = tabViewsForward
		} else {
			tabMap = tabViewsBackward
		}

		cycleView(app, isTab, tabMap)

	} else if isrune && evk.Rune() == '|' {
		if mainViewNoKeys.SubWidget() == mainview {
			mainViewNoKeys.SetSubWidget(altview1, app)
			profiles.SetConf("main.layout", "altview1")
		} else if mainViewNoKeys.SubWidget() == altview1 {
			mainViewNoKeys.SetSubWidget(altview2, app)
			profiles.SetConf("main.layout", "altview2")
		} else {
			mainViewNoKeys.SetSubWidget(mainview, app)
			profiles.SetConf("main.layout", "mainview")
		}
	} else if isrune && evk.Rune() == '\\' {
		w := mainViewNoKeys.SubWidget()
		fp := gowid.FocusPath(w)
		if w == viewOnlyPacketList || w == viewOnlyPacketStructure || w == viewOnlyPacketHex {
			switch profiles.ConfString("main.layout", "mainview") {
			case "altview1":
				mainViewNoKeys.SetSubWidget(altview1, app)
			case "altview2":
				mainViewNoKeys.SetSubWidget(altview2, app)
			default:
				mainViewNoKeys.SetSubWidget(mainview, app)
			}
			if deep.Equal(fp, maxViewPath) == nil {
				switch w {
				case viewOnlyPacketList:
					setFocusOnPacketList(app)
				case viewOnlyPacketStructure:
					setFocusOnPacketStruct(app)
				case viewOnlyPacketHex:
					setFocusOnPacketList(app)
				}
			}
		} else {
			gotov := 0
			if mainViewNoKeys.SubWidget() == mainview {
				v1p := gowid.FocusPath(mainview)
				if deep.Equal(v1p, mainviewPaths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v1p, mainviewPaths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			} else if mainViewNoKeys.SubWidget() == altview1 {
				v2p := gowid.FocusPath(altview1)
				if deep.Equal(v2p, altview1Paths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v2p, altview1Paths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			} else if mainViewNoKeys.SubWidget() == altview2 {
				v3p := gowid.FocusPath(altview2)
				if deep.Equal(v3p, altview2Paths[0]) == nil {
					gotov = 0
				} else if deep.Equal(v3p, altview2Paths[1]) == nil {
					gotov = 1
				} else {
					gotov = 2
				}
			}

			switch gotov {
			case 0:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketList, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
				}
			case 1:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketStructure, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
				}
			case 2:
				mainViewNoKeys.SetSubWidget(viewOnlyPacketHex, app)
				if deep.Equal(fp, maxViewPath) == nil {
					gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)
				}
			}

		}
	} else if isrune && evk.Rune() == '/' {
		setFocusOnDisplayFilter(app)
	} else {
		handled = false
	}
	return handled
}

func focusOnMenuButton(app gowid.IApp) {
	gowid.SetFocusPath(mainview, menuPathMain, app)
	gowid.SetFocusPath(altview1, menuPathAlt, app)
	gowid.SetFocusPath(altview2, menuPathAlt, app)
	gowid.SetFocusPath(viewOnlyPacketList, menuPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketStructure, menuPathMax, app)
	gowid.SetFocusPath(viewOnlyPacketHex, menuPathMax, app)
}

func openGeneralMenu(app gowid.IApp) {
	focusOnMenuButton(app)
	multiMenu1Opener.OpenMenu(generalMenu, openMenuSite, app)
}

// Keys for the whole app, applicable whichever view is frontmost
func appKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	isrune := evk.Key() == tcell.KeyRune

	if evk.Key() == tcell.KeyCtrlC {
		reallyQuit(app)
	} else if evk.Key() == tcell.KeyCtrlL {
		app.Sync()
	} else if isrune && (evk.Rune() == 'q' || evk.Rune() == 'Q') {
		reallyQuit(app)
	} else if isrune && evk.Rune() == ':' {
		lastLineMode(app)
	} else if evk.Key() == tcell.KeyEscape {
		focusOnMenuButton(app)
	} else if isrune && evk.Rune() == '?' {
		OpenTemplatedDialog(appView, "UIHelp", app)
	} else if isrune && evk.Rune() == 'Z' && keyState.PartialZCmd {
		RequestQuit()
	} else if isrune && evk.Rune() == 'Z' {
		keyState.PartialZCmd = true
	} else if isrune && evk.Rune() == 'm' {
		keyState.PartialmCmd = true
	} else if isrune && evk.Rune() == '\'' {
		keyState.PartialQuoteCmd = true
	} else if isrune && evk.Rune() == 'g' {
		keyState.PartialgCmd = true
	} else if evk.Key() == tcell.KeyCtrlW {
		keyState.PartialCtrlWCmd = true
	} else if isrune && evk.Rune() >= '0' && evk.Rune() <= '9' {
		if keyState.NumberPrefix == -1 {
			keyState.NumberPrefix = int(evk.Rune() - '0')
		} else {
			keyState.NumberPrefix = (10 * keyState.NumberPrefix) + (int(evk.Rune() - '0'))
		}
	} else {
		handled = false
	}
	return handled
}

type LoadResult struct {
	packetTree []*pdmltree.Model
	headers    []string
	packetList [][]string
}

func IsProgressIndeterminate() bool {
	return progressHolder.SubWidget() == loadSpinner
}

func SetProgressDeterminateFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner == 0 || progressOwner == owner {
		progressOwner = owner
		progressHolder.SetSubWidget(loadProgress, app)
	}
}

func SetProgressIndeterminateFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner == 0 || progressOwner == owner {
		progressOwner = owner
		progressHolder.SetSubWidget(loadSpinner, app)
	}
}

func ClearProgressWidgetFor(app gowid.IApp, owner WidgetOwner) {
	if progressOwner != owner {
		return
	}

	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = nullw
	ds[progWidgetIdx] = fixed
	filterCols.SetSubWidgets(sw, app)
	filterCols.SetDimensions(ds, app)

	progressOwner = NoOwner
}

func createLoaderProgressWidget() (*button.Widget, *columns.Widget) {
	btn, cols := createProgressWidget()

	btn.OnClick(gowid.MakeWidgetCallback("loaderstop", func(app gowid.IApp, w gowid.IWidget) {
		Loader.StopLoadPsmlAndIface(NoHandlers{}) // psml and iface
	}))

	return btn, cols
}

func createProgressWidget() (*button.Widget, *columns.Widget) {
	stop := button.New(text.New("Stop"))
	stop2 := styled.NewExt(stop, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))

	prog := vpadding.New(progressHolder, gowid.VAlignTop{}, flow)
	prog2 := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: prog,
			D:       weight(1),
		},
		colSpace,
		&gowid.ContainerWidget{
			IWidget: stop2,
			D:       fixed,
		},
	})

	return stop, prog2
}

func SetProgressWidget(app gowid.IApp) {
	SetProgressWidgetCustom(app, loadProg, LoaderOwns)
}

func SetSearchProgressWidget(app gowid.IApp) {
	SetProgressWidgetCustom(app, searchProg, SearchOwns)
}

func SetProgressWidgetCustom(app gowid.IApp, c *columns.Widget, owner WidgetOwner) {

	if progressOwner != owner && progressOwner != 0 {
		return
	}

	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = c
	ds[progWidgetIdx] = weight(33)
	filterCols.SetSubWidgets(sw, app)
	filterCols.SetDimensions(ds, app)
}

// setLowerWidgets will set the packet structure and packet hex views, if there
// is suitable data to display. If not, they are left as-is.
func setLowerWidgets(app gowid.IApp) {
	var sw1 gowid.IWidget
	var sw2 gowid.IWidget
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			row2, _ := packetListView.Model().RowIdentifier(fxy.Row)
			row := int(row2)

			hex := getHexWidgetToDisplay(row)
			if hex != nil {
				sw1 = enableselected.New(
					withscrollbar.New(
						hex,
						withscrollbar.Options{
							HideIfContentFits: true,
						},
					),
				)
			}

			str := getStructWidgetToDisplay(row, app)
			if str != nil {
				sw2 = enableselected.New(str)
			}
		}
	}
	if sw1 != nil {
		packetHexViewHolder.SetSubWidget(sw1, app)
		StopEmptyHexViewTimer()
	} else {
		// If autoscroll is on, it's annoying to see the constant loading message, so
		// suppress and just remain on the last displayed hex
		timer := false
		if AutoScroll {
			// Only displaying loading if the current panel is blank. If it's data, leave the data
			if packetHexViewHolder.SubWidget() == nullw {
				timer = true
			}
		} else {
			if packetHexViewHolder.SubWidget() != MissingMsgw {
				timer = true
			}
		}

		if timer {
			if EmptyHexViewTimer == nil {
				EmptyHexViewTimer = time.AfterFunc(time.Duration(1000)*time.Millisecond, func() {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						singlePacketViewMsgHolder.SetSubWidget(Loadingw, app)
						packetHexViewHolder.SetSubWidget(MissingMsgw, app)
					}))
				})
			}
		}
	}
	if sw2 != nil {
		packetStructureViewHolder.SetSubWidget(sw2, app)
		StopEmptyStructViewTimer()
	} else {
		timer := false
		if AutoScroll {
			if packetStructureViewHolder.SubWidget() == nullw {
				timer = true
			}
		} else {
			if packetStructureViewHolder.SubWidget() != MissingMsgw {
				timer = true
			}
		}

		// If autoscroll is on, it's annoying to see the constant loading message, so
		// suppress and just remain on the last displayed hex
		if timer {
			if EmptyStructViewTimer == nil {
				EmptyStructViewTimer = time.AfterFunc(time.Duration(1000)*time.Millisecond, func() {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						singlePacketViewMsgHolder.SetSubWidget(Loadingw, app)
						packetStructureViewHolder.SetSubWidget(MissingMsgw, app)
					}))
				})
			}
		}
	}

}

func makePacketListModel(psml iPsmlInfo, app gowid.IApp) *psmlmodel.Model {
	headers := psml.PsmlHeaders()

	avgs := psml.PsmlAverageLengths()
	maxs := psml.PsmlMaxLengths()
	widths := make([]gowid.IWidgetDimension, 0, len(avgs))
	for i := 0; i < len(avgs); i++ {
		titleLen := 0
		if i < len(headers) {
			titleLen = len(headers[i]) + 1 // add 1 because the table clears the last cell
		}
		max := gwutil.Max(maxs[i], titleLen)

		// in case there isn't any data yet
		avg := titleLen
		if !avgs[i].IsNone() {
			avg = gwutil.Max(avgs[i].Val(), titleLen)
		}
		// This makes the UI look nicer - an extra column of space when the columns are
		// packed tightly and each column is usually full.
		if avg == max {
			widths = append(widths, weightupto(avg, max+1))
		} else {
			widths = append(widths, weightupto(avg, max))
		}
	}

	packetPsmlTableModel := table.NewSimpleModel(
		headers,
		psml.PsmlData(),
		table.SimpleOptions{
			Style: table.StyleOptions{
				VerticalSeparator:   fill.New(' '),
				HeaderStyleProvided: true,
				HeaderStyleFocus:    gowid.MakePaletteRef("packet-list-cell-focus"),
				CellStyleProvided:   true,
				CellStyleSelected:   gowid.MakePaletteRef("packet-list-cell-selected"),
				CellStyleFocus:      gowid.MakePaletteRef("packet-list-cell-focus"),
			},
			Layout: table.LayoutOptions{
				Widths: widths,
			},
		},
	)

	expandingModel := psmlmodel.New(
		packetPsmlTableModel,
		gowid.MakePaletteRef("packet-list-row-focus"),
	)

	// No need to refetch the information from the TOML file each time this is
	// called. Use a globally cached version
	cols := shark.GetPsmlColumnFormatCached()

	if len(expandingModel.Comparators) > 0 {
		for i, _ := range expandingModel.Comparators {
			if i < len(widths) && i < len(cols) {
				if field, ok := shark.AllowedColumnFormats[cols[i].Field.Token]; ok {
					if field.Comparator != nil {
						expandingModel.Comparators[i] = field.Comparator
					}
				}
			}
		}
	}

	return expandingModel
}

func updatePacketListWithData(psml iPsmlInfo, app gowid.IApp) {
	packetListView.colors = psml.PsmlColors() // otherwise this isn't updated
	model := makePacketListModel(psml, app)
	newPacketsArrived = true
	packetListTable.SetModel(model, app)
	newPacketsArrived = false
	if AutoScroll {
		coords, err := packetListView.FocusXY()
		if err == nil {
			coords.Row = packetListTable.Length() - 1
			newPacketsArrived = true
			// Set focus on the last item in the view, then...
			packetListView.SetFocusXY(app, coords)
			newPacketsArrived = false
		}
		// ... adjust the widget so it is rendering with the last item at the bottom.
		packetListTable.GoToBottom(app)
	}
	// Only do this once, the first time.
	if !packetListView.didFirstAutoFocus && len(psml.PsmlData()) > 0 {
		packetListView.SetFocusOnData(app)
		packetListView.didFirstAutoFocus = true
	}
}

// don't claim the keypress
func ApplyAutoScroll(ev *tcell.EventKey, app gowid.IApp) bool {
	doit := false
	reenableAutoScroll = false
	switch ev.Key() {
	case tcell.KeyRune:
		if ev.Rune() == 'G' {
			doit = true
		}
	case tcell.KeyEnd:
		doit = true
	}
	if doit {
		if profiles.ConfBool("main.auto-scroll", true) {
			AutoScroll = true
			reenableAutoScroll = true // when packet updates come, helps
			// understand that AutoScroll should not be disabled again
		}
	}
	return false
}

type iPsmlInfo interface {
	PsmlData() [][]string
	PsmlHeaders() []string
	PsmlColors() []pcap.PacketColors
	PsmlAverageLengths() []gwutil.IntOption
	PsmlMaxLengths() []int
}

func setPacketListWidgets(psml iPsmlInfo, app gowid.IApp) {
	expandingModel := makePacketListModel(psml, app)

	packetListTable = &table.BoundedWidget{Widget: table.New(expandingModel)}
	packetListView = NewPsmlTableRowWidget(
		NewRowFocusTableWidget(
			packetListTable,
			"packet-list-row-selected",
			"packet-list-row-focus",
		),
		psml.PsmlColors(),
	)

	packetListView.OnFocusChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		fxy, err := packetListView.FocusXY()
		if err != nil {
			return
		}

		if !newPacketsArrived && !reenableAutoScroll {
			// this focus change must've been user-initiated, so stop auto-scrolling with new packets.
			// This mimics Wireshark's behavior. Note that if the user hits the end key, this may
			// update the view and run this callback, but end means to resume auto-scrolling if it's
			// enabled, so we should not promptly disable it again
			AutoScroll = false
		}

		row2 := fxy.Row
		row3, gotrow := packetListView.Model().RowIdentifier(row2)
		row := int(row3)

		if gotrow && row >= 0 {

			pktsPerLoad := Loader.PacketsPerLoad()

			rowm := row % pktsPerLoad

			CacheRequests = CacheRequests[:0]

			CacheRequests = append(CacheRequests, pcap.LoadPcapSlice{
				Row:           (row / pktsPerLoad) * pktsPerLoad,
				CancelCurrent: true,
			})
			if rowm > pktsPerLoad/2 {
				// Optimistically load the batch below this one
				CacheRequests = append(CacheRequests, pcap.LoadPcapSlice{
					Row: ((row / pktsPerLoad) + 1) * pktsPerLoad,
				})
			} else {
				// Optimistically load the batch above this one
				row2 := ((row / pktsPerLoad) - 1) * pktsPerLoad
				if row2 < 0 {
					row2 = 0
				}
				CacheRequests = append(CacheRequests, pcap.LoadPcapSlice{
					Row: row2,
				})
			}

			CacheRequestsChan <- struct{}{}
		}

		// When the focus changes, update the hex and struct view. If they cannot
		// be populated, display a loading message

		setLowerWidgets(app)
	}))

	withScrollbar := withscrollbar.New(packetListView, withscrollbar.Options{
		HideIfContentFits: true,
	})
	selme := enableselected.New(withScrollbar)
	keys := appkeys.New(
		selme,
		tableutil.GotoHandler(&tableutil.GoToAdapter{
			BoundedWidget: packetListTable,
			KeyState:      &keyState,
		}),
	)

	packetListViewHolder.SetSubWidget(keys, app)
}

func expandStructWidgetAtPosition(row int, pos int, app gowid.IApp) {
	if curPacketStructWidget != nil {
		walker := curPacketStructWidget.Walker().(*noroot.Walker)
		curTree := walker.Tree().(*pdmltree.Model)

		finalPos := make([]int, 0)

		// hack accounts for the fact we always skip the first two nodes in the pdml tree but
		// only at the first level
		hack := 1
	Out:
		for {
			chosenIdx := -1
			var chosenTree *pdmltree.Model
			for i, ch := range curTree.Children_[hack:] {
				// Save the current best one - but keep going. The pdml does not necessarily present them sorted
				// by position. So we might need to skip one to find the best fit.
				if ch.Pos <= pos && pos < ch.Pos+ch.Size {
					chosenTree = ch
					chosenIdx = i
				}
			}
			if chosenTree != nil {
				chosenTree.SetCollapsed(app, false)
				finalPos = append(finalPos, chosenIdx+hack)
				curTree = chosenTree
				hack = 0
			} else {
				// didn't find any
				break Out
			}
		}
		if len(finalPos) > 0 {
			curStructPosition = tree.NewPosExt(finalPos)
			// this is to account for the fact that noRootWalker returns the next widget
			// in the tree. Whatever position we find, we need to go back one to make up for this.
			walker.SetFocus(curStructPosition, app)

			curPacketStructWidget.GoToMiddle(app)
			curStructWidgetState = curPacketStructWidget.State()

			updateCurrentPdmlPosition(walker.Tree())
		}
	}
}

func updateCurrentPdmlPosition(tr tree.IModel) {
	updateCurrentPdmlPositionFrom(tr, curStructPosition)
}

func updateCurrentPdmlPositionFrom(tr tree.IModel, pos tree.IPos) {
	treeAtCurPos := pos.GetSubStructure(tr)
	// Save [/, tcp, tcp.srcport] - so we can apply if user moves in packet list
	curPdmlPosition = treeAtCurPos.(*pdmltree.Model).PathToRoot()
}

func getLayersFromStructWidget(row int, pos int) []hexdumper2.LayerStyler {
	layers := make([]hexdumper2.LayerStyler, 0)

	model := getCurrentStructModel(row)
	if model != nil {
		layers = model.HexLayers(pos, false)
	}

	return layers
}

func getHexWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("p%d", row))
}

// Can return nil
func getHexWidgetToDisplay(row int) *hexdumper2.Widget {
	var res2 *hexdumper2.Widget

	if val, ok := packetHexWidgets.Get(row); ok {
		res2 = val.(*hexdumper2.Widget)
	} else {
		pktsPerLoad := Loader.PacketsPerLoad()

		row2 := (row / pktsPerLoad) * pktsPerLoad
		if ws, ok := Loader.PacketCache.Get(row2); ok {
			srca := ws.(pcap.CacheEntry).Pcap
			if len(srca) > row%pktsPerLoad {
				src := srca[row%pktsPerLoad]
				b := make([]byte, len(src))
				copy(b, src)

				layers := getLayersFromStructWidget(row, 0)
				res2 = hexdumper2.New(b, hexdumper2.Options{
					StyledLayers:      layers,
					CursorUnselected:  "hex-byte-unselected",
					CursorSelected:    "hex-byte-selected",
					LineNumUnselected: "hex-interval-unselected",
					LineNumSelected:   "hex-interval-selected",
					PaletteIfCopying:  "copy-mode",
				})

				// If the user moves the cursor in the hexdump, this callback will adjust the corresponding
				// pdml tree/struct widget's currently selected layer. That in turn will result in a callback
				// to the hex widget to set the active layers.
				res2.OnPositionChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, target gowid.IWidget) {
					// If we're not focused on hex, then don't expand the struct widget. That's because if
					// we're focused on struct, then changing the struct position causes a callback to the
					// hex to update layers - which can update the hex position - which invokes a callback
					// to change the struct again. So ultimately, moving the struct moves the hex position
					// which moves the struct and causes the struct to jump around. I need to check
					// the alt view too because the user can click with the mouse and in one view have
					// struct selected but in the other view have hex selected.

					// Propagate the adjustments to pane positions if:
					// - this was initiated from a non-struct pane e.g. the hex pane. Then we update struct
					// - this was via an override e.g. search for packet bytes. Then hex is updated on match
					//   which should then update the struct view
					if currentlyFocusedViewNotStruct() || allowHexToStructRepositioning {
						expandStructWidgetAtPosition(row, res2.Position(), app)
					}

					// Ensure the behavior is reset after this callback runs. Just do it once.
					allowHexToStructRepositioning = false
				}))

				packetHexWidgets.Add(row, res2)
			}
		}
	}
	return res2
}

//======================================================================

// pdmlFilterActor closes the menus opened via the PDML struct view, then
// either applies or preps the appropriate display filter
type pdmlFilterActor struct {
	filter  string
	prepare bool
	menu1   *menu.Widget
	menu2   *menu.Widget
}

var _ iFilterMenuActor = (*pdmlFilterActor)(nil)

func (p *pdmlFilterActor) HandleFilterMenuSelection(comb FilterCombinator, app gowid.IApp) {
	multiMenu2Opener.CloseMenu(p.menu2, app)
	multiMenu1Opener.CloseMenu(p.menu1, app)

	filter := ComputeFilterCombOp(comb, p.filter, FilterWidget.Value())

	FilterWidget.SetValue(filter, app)

	if p.prepare {
		// Don't run the filter, just add to the displayfilter widget. Leave focus there
		setFocusOnDisplayFilter(app)
	} else {
		RequestNewFilter(filter, app)
	}

}

//======================================================================

func getStructWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("s%d", row))
}

// Note - hex can be nil
// Note - returns nil if one can't be found
func getStructWidgetToDisplay(row int, app gowid.IApp) gowid.IWidget {
	var res gowid.IWidget

	model := getCurrentStructModel(row)
	if model != nil {

		// Apply expanded paths from previous packet
		model.ApplyExpandedPaths(&curExpandedStructNodes)
		model.Expanded = true

		var pos tree.IPos = tree.NewPos()
		pos = tree.NextPosition(pos, model) // Start ahead by one, then never go back

		rwalker := tree.NewWalker(model, pos,
			tree.NewCachingMaker(tree.WidgetMakerFunction(makeStructNodeWidget)),
			tree.NewCachingDecorator(tree.DecoratorFunction(makeStructNodeDecoration)))
		// Without the caching layer, clicking on a button has no effect
		walker := noroot.NewWalker(rwalker)

		// Send the layers represents the tree expansion to hex.
		// This could be the user clicking inside the tree. Or it might be the position changing
		// in the hex widget, resulting in a callback to programmatically change the tree expansion,
		// which then calls back to the hex
		updateHex := func(app gowid.IApp, doCursor bool, twalker tree.ITreeWalker) {

			newhex := getHexWidgetToDisplay(row)
			if newhex != nil {

				newtree := twalker.Tree().(*pdmltree.Model)
				newpos := twalker.Focus().(tree.IPos)

				expTree := (*pdmltree.ExpandedModel)(twalker.Tree().(*pdmltree.Model))

				leaf := newpos.GetSubStructure(expTree).(*pdmltree.ExpandedModel)

				coverWholePacket := false

				// This skips the "frame" node in the pdml that covers the entire range of bytes. If newpos
				// is [0] then the user has chosen that node by interacting with the struct view (the hex view
				// can't choose any position that maps to the first pdml child node) - so in this case, we
				// send back a layer spanning the entire packet. Otherwise we don't want to send back that
				// packet-spanning layer because it will always be the layer returned, meaning the hexdumper2
				// will always show the entire packet highlighted.
				if newpos.Equal(tree.NewPosExt([]int{0})) {
					coverWholePacket = true
				}

				newLayers := newtree.HexLayers(leaf.Pos, coverWholePacket)
				if len(newLayers) > 0 {
					newhex.SetLayers(newLayers, app)

					// If the hex view is changed by the user (or SetPosition), which then causes a callback to update
					// the struct view - which then causes a callback to update the hex layer - the cursor can move in
					// such a way it stays inside a valid layer and can't get outside. This boolean controls that
					if doCursor {
						curhexpos := newhex.Position()
						smallestlayer := newLayers[len(newLayers)-1]

						if !(smallestlayer.Start <= curhexpos && curhexpos < smallestlayer.End) {
							// The reason for this is to ensure the hex cursor moves according to the current struct
							// layer - otherwise when you tab to the hex layer, you immediately lose your struct layer
							// when you move the cursor - because it's outside of your struct context.
							newhex.SetPosition(smallestlayer.Start, app)
						}
					}
				}
			}

		}

		tb := copymodetree.New(tree.New(walker), copyModePalette{})
		res = tb
		// Save this in case the hex layer needs to change it

		curPacketStructWidget = tb

		// If not nil, it means we're re-rendering this part of the UI because of a hit in a packet
		// struct search. So set the struct position, and then the next block of code will adjust the
		// UI to focus on the part of the struct that matched the search.
		if curSearchPosition != nil {
			curStructPosition = curSearchPosition
		}

		if curStructPosition != nil {
			// if not nil, it means the user has interacted with some struct widget at least once causing
			// a focus change. We track the current focus e.g. [0, 2, 1] - the indices through the tree leading
			// to the focused item. We programmatically adjust the focus widget of the new struct (e.g. after
			// navigating down one in the packet list), but only if we can move focus to the same PDML field
			// as the old struct. For example, if we are on tcp.srcport in the old packet, and we can
			// open up tcp.srcport in the new packet, then we do so. This is not perfect, because I use the old
			// pdml tree position, which is a sequence of integer indices. This means if the next packet has
			// an extra layer before TCP, say some encapsulation, then I could still open up tcp.srcport, but
			// I don't find it because I find the candidate focus widget using the list of integer indices.

			curPos := curStructPosition // e.g. [0, 2, 1]
			expTree := (*pdmltree.ExpandedModel)(walker.Tree().(*pdmltree.Model))
			treeAtCurPos := curPos.GetSubStructure(expTree) // e.g. the TCP *pdmltree.Model
			if treeAtCurPos != nil {
				// If curSearchPosition != nil, it means out saved path will definitely be a hit in this
				// struct, so we are guaranteed to be able to apply it to the current tree walker. If
				// curSearchPosition == nil, it means we try our best to apply the previous position to
				// the current struct, knowing that the packet structure might be different.
				if curSearchPosition != nil || deep.Equal(curPdmlPosition, (*pdmltree.Model)(treeAtCurPos.(*pdmltree.ExpandedModel)).PathToRoot()) == nil {
					// if the newly selected struct has a node at [0, 2, 1] and it maps to tcp.srcport via the same path,
					// set the focus widget of the new struct i.e. which leaf has focus
					walker.SetFocus(curPos, app)

					if curStructWidgetState != nil {
						// we scrolled the previous struct a bit, apply it to the new one too
						tb.SetState(curStructWidgetState, app)
					} else {
						// First change by the user, so remember it and use it when navigating to the next
						curStructWidgetState = tb.State()
					}
				}
			}

		} else {
			curStructPosition = walker.Focus().(tree.IPos)
		}

		if curSearchPosition != nil {
			curPacketStructWidget.GoToMiddle(app)
			// Reset so as we move up and down, after a search, we do our best to preserve the
			// position, but we're not misled into thinking we have a guaranteed hit on the position.
			curSearchPosition = nil
		}

		tb.OnFocusChanged(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			curStructWidgetState = tb.State()
		})))

		walker.OnFocusChanged(tree.MakeCallback("cb", func(app gowid.IApp, twalker tree.ITreeWalker) {
			updateHex(app, currentlyFocusedViewNotHex(), twalker)

			// need to save the position, so it can be applied to the next struct widget
			// if brought into focus by packet list navigation
			curStructPosition = walker.Focus().(tree.IPos)

			updateCurrentPdmlPosition(walker.Tree())
		}))
	}
	return res
}

//======================================================================

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

func RequestLoadInterfaces(psrcs []pcap.IPacketSource, captureFilter string, displayFilter string, tmpfile string, app gowid.IApp) {
	Loader.Renew()
	Loader.LoadInterfaces(psrcs, captureFilter, displayFilter, tmpfile,
		pcap.HandlerList{
			StartUIWhenThereArePackets{},
			SimpleErrors{},
			MakeSaveRecents("", displayFilter),
			MakePacketViewUpdater(),
			MakeUpdateCurrentCaptureInTitle(),
			ManageStreamCache{},
			ManageCapinfoCache{},
			SetStructWidgets{Loader}, // for OnClear
			ClearWormholeState{},
			ClearMarksHandler{},
			ManageSearchData{},
			CancelledMessage{},
		},
		app,
	)
}

//======================================================================

// MaybeKeepThenRequestLoadPcap loads a pcap after first checking to see whether
// the current load is a live load and the packets need to be kept.
func MaybeKeepThenRequestLoadPcap(pcapf string, displayFilter string, jump termshark.GlobalJumpPos, app gowid.IApp) {
	if Loader.InterfaceFile() != "" && !WriteToSelected && !profiles.ConfBool("main.always-keep-pcap", false) {
		askToSave(app, func(app gowid.IApp) {
			RequestLoadPcap(pcapf, displayFilter, jump, app)
		})
	} else {
		RequestLoadPcap(pcapf, displayFilter, jump, app)
	}
}

// Call from app goroutine context
func RequestLoadPcap(pcapf string, displayFilter string, jump termshark.GlobalJumpPos, app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakeSaveRecents(pcapf, displayFilter),
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		ManageStreamCache{},
		ManageCapinfoCache{},
		SetStructWidgets{Loader}, // for OnClear
		MakeCheckGlobalJumpAfterPsml(jump),
		ClearWormholeState{},
		ClearMarksHandler{},
		ManageSearchData{},
		CancelledMessage{},
	}

	if _, err := os.Stat(pcapf); os.IsNotExist(err) {
		pcap.HandleError(pcap.NoneCode, app, err, handlers)
	} else {
		// no auto-scroll when reading a file
		AutoScroll = false
		Loader.LoadPcap(pcapf, displayFilter, handlers, app)
	}
}

//======================================================================

func RequestNewFilter(displayFilter string, app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakeSaveRecents("", displayFilter),
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		SetStructWidgets{Loader}, // for OnClear
		ClearMarksHandler{},
		ManageSearchData{},
		// Don't use this one - we keep the cancelled flag set so that we
		// don't restart live captures on clear if ctrl-c has been issued
		// so we don't want this handler on a new filter because we don't
		// want to be told again after applying the filter that the load
		// was cancelled
		//MakeCancelledMessage(),
	}

	if Loader.DisplayFilter() == displayFilter {
		log.Infof("No operation - same filter applied ('%s').", displayFilter)
	} else {
		Loader.Reload(displayFilter, handlers, app)
	}
}

func RequestReload(app gowid.IApp) {
	handlers := pcap.HandlerList{
		SimpleErrors{},
		MakePacketViewUpdater(),
		MakeUpdateCurrentCaptureInTitle(),
		SetStructWidgets{Loader}, // for OnClear
		ClearMarksHandler{},
		ManageSearchData{},
		// Don't use this one - we keep the cancelled flag set so that we
		// don't restart live captures on clear if ctrl-c has been issued
		// so we don't want this handler on a new filter because we don't
		// want to be told again after applying the filter that the load
		// was cancelled
		//MakeCancelledMessage(),
	}

	Loader.Reload(Loader.DisplayFilter(), handlers, app)
}

//======================================================================

// Prog hold a progress model - a current value on the way up to the max value
type Prog struct {
	cur int64
	max int64
}

func (p Prog) Complete() bool {
	return p.cur >= p.max
}

func (p Prog) String() string {
	return fmt.Sprintf("cur=%d max=%d", p.cur, p.max)
}

func (p Prog) Div(y int64) Prog {
	p.cur /= y
	return p
}

func (p Prog) Add(y Prog) Prog {
	return Prog{cur: p.cur + y.cur, max: p.max + y.max}
}

func progMin(x, y Prog) Prog {
	if float64(x.cur)/float64(x.max) < float64(y.cur)/float64(y.max) {
		return x
	} else {
		return y
	}
}

func progMax(x, y Prog) Prog {
	if float64(x.cur)/float64(x.max) > float64(y.cur)/float64(y.max) {
		return x
	} else {
		return y
	}
}

//======================================================================

func makeRecentMenuWidget() (gowid.IWidget, int) {
	savedItems := make([]menuutil.SimpleMenuItem, 0)
	cfiles := profiles.ConfStringSlice("main.recent-files", []string{})
	if cfiles != nil {
		for i, s := range cfiles {
			scopy := s
			savedItems = append(savedItems,
				menuutil.SimpleMenuItem{
					Txt: s,
					Key: gowid.MakeKey('a' + rune(i)),
					CB: func(app gowid.IApp, w gowid.IWidget) {
						multiMenu1Opener.CloseMenu(savedMenu, app)
						// capFilter global, set up in cmain()
						MaybeKeepThenRequestLoadPcap(scopy, FilterWidget.Value(), NoGlobalJump, app)
					},
				},
			)
		}
	}
	return menuutil.MakeMenuWithHotKeys(savedItems, nil)
}

func UpdateRecentMenu(app gowid.IApp) {
	savedListBox, _ := makeRecentMenuWidget()
	savedListBoxWidgetHolder.SetSubWidget(savedListBox, app)
}

//======================================================================

type savedCompleterCallback struct {
	prefix string
	comp   fields.IPrefixCompleterCallback
}

var _ fields.IPrefixCompleterCallback = (*savedCompleterCallback)(nil)

func (s *savedCompleterCallback) Call(orig []string) {
	if s.prefix == "" {
		comps := profiles.ConfStrings("main.recent-filters")
		if len(comps) == 0 {
			comps = orig
		}
		s.comp.Call(comps)
	} else {
		s.comp.Call(orig)
	}
}

type savedCompleter struct {
	def fields.IPrefixCompleter
}

var _ fields.IPrefixCompleter = (*savedCompleter)(nil)

func (s savedCompleter) Completions(prefix string, cb fields.IPrefixCompleterCallback) {
	ncomp := &savedCompleterCallback{
		prefix: prefix,
		comp:   cb,
	}
	s.def.Completions(prefix, ncomp)
}

//======================================================================

func StopEmptyStructViewTimer() {
	if EmptyStructViewTimer != nil {
		EmptyStructViewTimer.Stop()
		EmptyStructViewTimer = nil
	}
}

func StopEmptyHexViewTimer() {
	if EmptyHexViewTimer != nil {
		EmptyHexViewTimer.Stop()
		EmptyHexViewTimer = nil
	}
}

//======================================================================

func assignTo(wp interface{}, w gowid.IWidget) gowid.IWidget {
	reflect.ValueOf(wp).Elem().Set(reflect.ValueOf(w))
	return w
}

//======================================================================

// prefixKeyWidget wraps a widget, and adjusts the state of the variables tracking
// "partial" key chords e.g. the first Z in ZZ, the first g in gg. It also resets
// the number prefix (which some commands use) - this is done if they key is not
// a number, and the last keypress wasn't the start of a key chord.
type prefixKeyWidget struct {
	gowid.IWidget
}

func (w *prefixKeyWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	// Save these first. If they are enabled now, any key should cancel them, so cancel
	// at the end.
	startingKeyState := keyState

	handled := w.IWidget.UserInput(ev, size, focus, app)
	switch ev := ev.(type) {
	case *tcell.EventKey:
		// If it was set this time around, whatever key was pressed resets it
		if startingKeyState.PartialgCmd {
			keyState.PartialgCmd = false
		}
		if startingKeyState.PartialZCmd {
			keyState.PartialZCmd = false
		}
		if startingKeyState.PartialCtrlWCmd {
			keyState.PartialCtrlWCmd = false
		}
		if startingKeyState.PartialmCmd {
			keyState.PartialmCmd = false
		}
		if startingKeyState.PartialQuoteCmd {
			keyState.PartialQuoteCmd = false
		}

		if ev.Key() != tcell.KeyRune || ev.Rune() < '0' || ev.Rune() > '9' {
			if !keyState.PartialZCmd && !keyState.PartialgCmd && !keyState.PartialCtrlWCmd {
				keyState.NumberPrefix = -1
			}
		}

	}
	return handled
}

//======================================================================

func SetDarkMode(mode bool) {
	DarkMode = mode
	profiles.SetConf("main.dark-mode", DarkMode)
}

func UpdateProfileWidget(name string, app gowid.IApp) {
	currentProfile.SetText(name, app)
	if name != "" && name != "default" {
		currentProfileWidgetHolder.SetSubWidget(currentProfileWidget, app)
	} else {
		currentProfileWidgetHolder.SetSubWidget(nullw, app)
	}
}

// vp and vc guaranteed to be non-nil
func ApplyCurrentProfile(app gowid.IApp, vp *viper.Viper, vc *viper.Viper) error {
	UpdateProfileWidget(profiles.CurrentName(), app)

	reload := false

	SetDarkMode(profiles.ConfBool("main.dark-mode", true))

	curWireshark := profiles.ConfStringFrom(vp, profiles.Default(), "main.wireshark-profile", "")
	newWireshark := profiles.ConfStringFrom(vc, profiles.Default(), "main.wireshark-profile", "")
	if curWireshark != newWireshark {
		reload = true
	}

	curcols := profiles.ConfStringSliceFrom(vp, profiles.Default(), "main.column-format", []string{})
	newcols := profiles.ConfStringSliceFrom(vc, profiles.Default(), "main.column-format", []string{})
	if !reflect.DeepEqual(newcols, curcols) {
		reload = true
	}

	if reload {
		RequestReload(app)
	}

	ApplyCurrentTheme(app)
	SetupColors()

	return nil
}

func ApplyCurrentTheme(app gowid.IApp) {
	var err error
	mode := app.GetColorMode()
	modeStr := theme.Mode(mode) // more concise
	themeName := profiles.ConfString(fmt.Sprintf("main.theme-%s", modeStr), "default")
	loaded := false
	if themeName != "" {
		err = theme.Load(themeName, app)
		if err != nil {
			log.Warnf("Theme %s could not be loaded: %v", themeName, err)
		} else {
			loaded = true
		}
	}
	if !loaded && themeName != "default" {
		err = theme.Load("default", app)
		if err != nil {
			log.Warnf("Theme %s could not be loaded: %v", themeName, err)
		}
	}
}

//======================================================================

func Build(tty string) (*gowid.App, error) {

	var err error
	var app *gowid.App

	widgetCacheSize := profiles.ConfInt("main.ui-cache-size", 1000)
	if widgetCacheSize < 64 {
		widgetCacheSize = 64
	}
	packetHexWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		return nil, gowid.WithKVs(termshark.InternalErr, map[string]interface{}{
			"err": err,
		})
	}

	nullw = null.New()

	Loadingw = text.New("Loading, please wait...")
	singlePacketViewMsgHolder = holder.New(nullw)
	fillSpace = fill.New(' ')
	if runtime.GOOS == "windows" {
		fillVBar = fill.New('|')
	} else {
		fillVBar = fill.New('┃')
	}

	colSpace = &gowid.ContainerWidget{
		IWidget: fillSpace,
		D:       units(1),
	}

	MissingMsgw = vpadding.New( // centred
		hpadding.New(singlePacketViewMsgHolder, hmiddle, fixed),
		vmiddle,
		flow,
	)

	pleaseWaitSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})

	PleaseWait = dialog.New(framed.NewSpace(
		pile.NewFlow(
			&gowid.ContainerWidget{
				IWidget: text.New(" Please wait... "),
				D:       gowid.RenderFixed{},
			},
			fillSpace,
			pleaseWaitSpinner,
		)),
		dialog.Options{
			Buttons:         dialog.NoButtons,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	title := styled.New(text.New(termshark.TemplateToString(Templates, "NameVer", TemplateData)), gowid.MakePaletteRef("title"))

	currentCapture = text.New("")
	currentCaptureStyled := styled.New(
		currentCapture,
		gowid.MakePaletteRef("current-capture"),
	)

	sp := text.New("  ")

	currentCaptureWidget = columns.NewFixed(
		sp,
		&gowid.ContainerWidget{
			IWidget: fill.New('|'),
			D:       gowid.MakeRenderBox(1, 1),
		},
		sp,
		currentCaptureStyled,
	)
	currentCaptureWidgetHolder = holder.New(nullw)

	CopyModePredicate = func() bool {
		return app != nil && app.InCopyMode()
	}

	CopyModeWidget = styled.New(
		ifwidget.New(
			text.New(" COPY-MODE "),
			null.New(),
			CopyModePredicate,
		),
		gowid.MakePaletteRef("copy-mode-label"),
	)

	//======================================================================

	openMenu := button.NewBare(text.New("  Misc  "))
	openMenu2 := clicktracker.New(
		styled.NewExt(
			openMenu,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)

	openMenuSite = menu.NewSite(menu.SiteOptions{YOffset: 1})
	openMenu.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		multiMenu1Opener.OpenMenu(generalMenu, openMenuSite, app)
	}))

	//======================================================================

	generalMenuItems := make([]menuutil.SimpleMenuItem, 0)

	generalMenuItems = append(generalMenuItems, []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: "Refresh Screen",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlL, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				app.Sync()
			},
		},
		// Put 2nd so a simple menu click, down, enter without thinking doesn't toggle dark mode (annoying...)
		menuutil.SimpleMenuItem{
			Txt: "Toggle Dark Mode",
			Key: gowid.MakeKey('d'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				SetDarkMode(!DarkMode)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Search Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlF, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !searchOpen() {
					filterHolder.SetSubWidget(filterWithSearch, app)
				}
				setFocusOnSearch(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Clear Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlW, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				reallyClear(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Send Pcap",
			Key: gowid.MakeKey('s'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openWormhole(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Edit Columns",
			Key: gowid.MakeKey('e'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openEditColumns(app)
			},
		}}...)

	if runtime.GOOS != "windows" {
		generalMenuItems = append(generalMenuItems, menuutil.SimpleMenuItem{
			Txt: "Show Log",
			Key: gowid.MakeKey('l'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openLogsUi(app)
			},
		})
		generalMenuItems = append(generalMenuItems, menuutil.SimpleMenuItem{
			Txt: "Show Config",
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				openConfigUi(app)
			},
		})
	}

	generalMenuItems = append(generalMenuItems, []menuutil.SimpleMenuItem{
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Help",
			Key: gowid.MakeKey('?'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				OpenTemplatedDialog(appView, "UIHelp", app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "User Guide",
			Key: gowid.MakeKey('u'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.UserGuideURL)
				}
				openResultsAfterCopy("UIUserGuide", termshark.UserGuideURL, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "FAQ",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.FAQURL)
				}
				openResultsAfterCopy("UIFAQ", termshark.FAQURL, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Found a Bug?",
			Key: gowid.MakeKey('b'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.BugURL)
				}
				openResultsAfterCopy("UIBug", termshark.BugURL, app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Feature Request?",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				if !termshark.RunningRemotely() {
					termshark.BrowseUrl(termshark.FeatureURL)
				}
				openResultsAfterCopy("UIFeature", termshark.FeatureURL, app)
			},
		},
		menuutil.MakeMenuDivider(),
		menuutil.SimpleMenuItem{
			Txt: "Quit",
			Key: gowid.MakeKey('q'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(generalMenu, app)
				reallyQuit(app)
			},
		},
	}...)

	if PacketColorsSupported {
		generalMenuItems = append(
			generalMenuItems[0:2],
			append(
				[]menuutil.SimpleMenuItem{
					menuutil.SimpleMenuItem{
						Txt: "Toggle Packet Colors",
						Key: gowid.MakeKey('c'),
						CB: func(app gowid.IApp, w gowid.IWidget) {
							multiMenu1Opener.CloseMenu(generalMenu, app)
							PacketColors = !PacketColors
							profiles.SetConf("main.packet-colors", PacketColors)
						},
					},
				},
				generalMenuItems[2:]...,
			)...,
		)
	}

	generalMenuListBox, generalMenuWidth := menuutil.MakeMenuWithHotKeys(generalMenuItems, nil)

	var generalNext menuutil.NextMenu

	generalMenuListBoxWithKeys := appkeys.New(
		generalMenuListBox,
		menuutil.MakeMenuNavigatingKeyPress(
			&generalNext,
			nil,
		),
	)

	// Hack. What's a more general way of doing this? The length of the <Menu> button I suppose
	openMenuSite.Options.XOffset = -generalMenuWidth + 8

	generalMenu = menu.New("main", generalMenuListBoxWithKeys, units(generalMenuWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	//======================================================================

	openAnalysis := button.NewBare(text.New("  Analysis  "))
	openAnalysis2 := clicktracker.New(
		styled.NewExt(
			openAnalysis,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)

	openAnalysisSite = menu.NewSite(menu.SiteOptions{XOffset: -12, YOffset: 1})
	openAnalysis.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		multiMenu1Opener.OpenMenu(analysisMenu, openAnalysisSite, app)
	}))

	analysisMenuItems := []menuutil.SimpleMenuItem{
		menuutil.SimpleMenuItem{
			Txt: "Capture file properties",
			Key: gowid.MakeKey('p'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				startCapinfo(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Reassemble stream",
			Key: gowid.MakeKey('f'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				startStreamReassembly(app)
			},
		},
		menuutil.SimpleMenuItem{
			Txt: "Conversations",
			Key: gowid.MakeKey('c'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				multiMenu1Opener.CloseMenu(analysisMenu, app)
				openConvsUi(app)
			},
		},
	}

	analysisMenuListBox, analysisMenuWidth := menuutil.MakeMenuWithHotKeys(analysisMenuItems, nil)

	var analysisNext menuutil.NextMenu

	analysisMenuListBoxWithKeys := appkeys.New(
		analysisMenuListBox,
		menuutil.MakeMenuNavigatingKeyPress(
			nil,
			&analysisNext,
		),
	)

	analysisMenu = menu.New("analysis", analysisMenuListBoxWithKeys, units(analysisMenuWidth), menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	//======================================================================

	loadProgress = progress.New(progress.Options{
		Normal:   gowid.MakePaletteRef("progress-default"),
		Complete: gowid.MakePaletteRef("progress-complete"),
	})

	loadSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})

	savedListBox, _ := makeRecentMenuWidget()
	savedListBoxWidgetHolder = holder.New(savedListBox)

	savedMenu = menu.New("saved", savedListBoxWidgetHolder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	//======================================================================

	currentProfile = text.New("default")
	currentProfileWidget = columns.NewFixed(
		text.New("Profile: "),
		currentProfile,
		sp,
		&gowid.ContainerWidget{
			IWidget: fill.New('|'),
			D:       gowid.MakeRenderBox(1, 1),
		},
		sp,
	)
	currentProfileWidgetHolder = holder.New(currentProfileWidget)

	// Update display to show the profile if it isn't the default
	UpdateProfileWidget(profiles.CurrentName(), app)

	var titleCols *columns.Widget

	// If anything gets added or removed here, see [[generalmenu1]]
	// and [[generalmenu2]] and [[generalmenu3]]
	titleView := overlay.New(
		hpadding.New(CopyModeWidget, gowid.HAlignMiddle{}, fixed),
		assignTo(&titleCols, columns.NewFixed(
			title,
			&gowid.ContainerWidget{
				IWidget: currentCaptureWidgetHolder,
				D:       weight(10), // give it priority when the window isn't wide enough
			},
			&gowid.ContainerWidget{
				IWidget: fill.New(' '),
				D:       weight(1),
			},
			&gowid.ContainerWidget{
				IWidget: currentProfileWidgetHolder,
				D:       fixed, // give it priority when the window isn't wide enough
			},
			openAnalysisSite,
			openAnalysis2,
			openMenuSite,
			openMenu2,
		)),
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

	// Fill this in once generalMenu is defined and titleView is defined
	// <<generalmenu1>>
	generalNext.Cur = generalMenu
	generalNext.Next = analysisMenu
	generalNext.Site = openAnalysisSite
	generalNext.Container = titleCols
	generalNext.MenuOpener = &multiMenu1Opener
	generalNext.Focus = 5 // should really find by ID

	// <<generalmenu2>>
	analysisNext.Cur = analysisMenu
	analysisNext.Next = generalMenu
	analysisNext.Site = openMenuSite
	analysisNext.Container = titleCols
	analysisNext.MenuOpener = &multiMenu1Opener
	analysisNext.Focus = 7 // should really find by ID

	packetListViewHolder = holder.New(nullw)
	packetStructureViewHolder = holder.New(nullw)
	packetHexViewHolder = holder.New(nullw)

	progressHolder = holder.New(nullw)

	applyw := button.New(text.New("Apply"))
	applyWidget := disable.NewEnabled(
		clicktracker.New(
			styled.NewExt(
				applyw,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
		),
	)

	// For completing filter expressions
	FieldCompleter = fields.New()
	FieldCompleter.Init()

	FilterWidget = filter.New("filter", filter.Options{
		Completer:  savedCompleter{def: FieldCompleter},
		MenuOpener: &multiMenu1Opener,
	})

	validFilterCb := gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		if Loader.DisplayFilter() == FilterWidget.Value() {
			OpenError("Same filter - nothing to do", app)
		} else {
			RequestNewFilter(FilterWidget.Value(), app)
		}
	})

	// Will only be enabled to click if filter is valid
	applyw.OnClick(validFilterCb)
	// Will only fire OnSubmit if filter is valid
	FilterWidget.OnSubmit(validFilterCb)

	FilterWidget.OnValid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Enable()
	}))
	FilterWidget.OnInvalid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Disable()
	}))
	filterLabel := text.New("Filter: ")

	savedw := button.New(text.New("Recent"))
	savedWidget := clicktracker.New(
		styled.NewExt(
			savedw,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	)
	savedBtnSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	savedw.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		multiMenu1Opener.OpenMenu(savedMenu, savedBtnSite, app)
		// if !multiMenu1Opener.OpenMenu(savedMenu, savedBtnSite, app) {
		// 	multiMenu1Opener.CloseMenu(savedMenu, app)
		// }
	}))

	progWidgetIdx = 7 // adjust this if nullw moves position in filterCols
	filterCols = columns.NewFixed(filterLabel,
		&gowid.ContainerWidget{
			IWidget: FilterWidget,
			D:       weight(100),
		},
		applyWidget, colSpace, savedBtnSite, savedWidget, colSpace, nullw)

	//======================================================================

	loadStop, loadProg = createLoaderProgressWidget()
	searchStop, searchProg = createProgressWidget()

	//======================================================================

	searchCh := make(chan search.IntermediateResult)

	cbs := &commonSearchCallbacks{}

	listSearchCallbacks := func() search.ICallbacks {
		return &ListSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	structSearchCallbacks := func() search.ICallbacks {
		return &StructSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	bytesSearchCallbacks := func() search.ICallbacks {
		return &BytesSearchCallbacks{
			commonSearchCallbacks: cbs,
			SearchStopper:         &SearchStopper{},
			search:                searchCh,
		}
	}

	filterSearchCallbacks := func() search.ICallbacks {
		return NewFilterSearchCallbacks(cbs, searchCh)
	}

	SearchWidget = search.New(
		&PacketSearcher{
			resultChan: searchCh,
		},
		listSearchCallbacks,
		structSearchCallbacks,
		bytesSearchCallbacks,
		filterSearchCallbacks,
		&multiMenu1Opener,
		savedCompleter{def: FieldCompleter},
		OpenErrorDialog{},
	)

	//======================================================================

	filterWithoutSearch = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: filterCols,
			D:       units(1),
		},
	})

	filterWithSearch = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: filterCols,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: fill.New('━'),
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: SearchWidget,
			D:       units(1),
		},
	})

	filterHolder = holder.New(filterWithoutSearch)

	filterView := framed.NewUnicode(filterHolder)

	// swallowMovementKeys will prevent cursor movement that is not accepted
	// by the main views (column or pile) to change focus e.g. moving from the
	// packet structure view to the packet list view. Often you'd want this
	// movement to be possible, but in termshark it's more often annoying -
	// you navigate to the top of the packet structure, hit up one more time
	// and you're in the packet list view accidentally, hit down instinctively
	// to go back and you change the selected packet.
	packetListViewWithKeys := appkeys.NewMouse(
		appkeys.New(
			appkeys.New(
				appkeys.New(
					packetListViewHolder,
					ApplyAutoScroll,
					appkeys.Options{
						ApplyBefore: true,
					},
				),
				appKeysResize1,
			),
			widgets.SwallowMovementKeys,
		),
		widgets.SwallowMouseScroll,
	)

	packetStructureViewWithKeys :=
		appkeys.New(
			appkeys.New(
				appkeys.NewMouse(
					appkeys.New(
						appkeys.New(
							packetStructureViewHolder,
							appKeysResize2,
						),
						widgets.SwallowMovementKeys,
					),
					widgets.SwallowMouseScroll,
				),
				copyModeEnterKeys,
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			copyModeExitKeys,
			appkeys.Options{
				ApplyBefore: true,
			},
		)

	packetHexViewHolderWithKeys :=
		appkeys.New(
			appkeys.New(
				appkeys.NewMouse(
					appkeys.New(
						packetHexViewHolder,
						widgets.SwallowMovementKeys,
					),
					widgets.SwallowMouseScroll,
				),
				copyModeEnterKeys,
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			copyModeExitKeys,
			appkeys.Options{
				ApplyBefore: true,
			},
		)

	mainviewRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetListViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolderWithKeys,
			D:       weight(1),
		},
	})

	mainviewRows.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("mainview", mainviewRows.GetOffsets())
	}))

	viewOnlyPacketList = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetListViewHolder,
			D:       weight(1),
		},
	})

	viewOnlyPacketStructure = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewHolder,
			D:       weight(1),
		},
	})

	viewOnlyPacketHex = pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolder,
			D:       weight(1),
		},
	})

	tabViewsForward = make(map[gowid.IWidget]gowid.IWidget)
	tabViewsBackward = make(map[gowid.IWidget]gowid.IWidget)

	tabViewsForward[viewOnlyPacketList] = viewOnlyPacketStructure
	tabViewsForward[viewOnlyPacketStructure] = viewOnlyPacketHex
	tabViewsForward[viewOnlyPacketHex] = viewOnlyPacketList

	tabViewsBackward[viewOnlyPacketList] = viewOnlyPacketHex
	tabViewsBackward[viewOnlyPacketStructure] = viewOnlyPacketList
	tabViewsBackward[viewOnlyPacketHex] = viewOnlyPacketStructure

	//======================================================================

	altview1Pile = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: packetListViewWithKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewWithKeys,
			D:       weight(1),
		},
	})

	altview1Pile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altviewleft", altview1Pile.GetOffsets())
	}))

	altview1PileAndKeys := appkeys.New(altview1Pile, altview1PileKeyPress)

	altview1Cols = resizable.NewColumns([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: altview1PileAndKeys,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: fillVBar,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolderWithKeys,
			D:       weight(1),
		},
	})

	altview1Cols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altviewright", altview1Cols.GetOffsets())
	}))

	altview1ColsAndKeys := appkeys.New(altview1Cols, altview1ColsKeyPress)

	altview1OuterRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: altview1ColsAndKeys,
			D:       weight(1),
		},
	})

	//======================================================================

	altview2ColsAndKeys := appkeys.New(
		assignTo(&altview2Cols,
			resizable.NewColumns([]gowid.IContainerWidget{
				&gowid.ContainerWidget{
					IWidget: packetStructureViewWithKeys,
					D:       weight(1),
				},
				&gowid.ContainerWidget{
					IWidget: fillVBar,
					D:       units(1),
				},
				&gowid.ContainerWidget{
					IWidget: packetHexViewHolderWithKeys,
					D:       weight(1),
				},
			}),
		),
		altview2ColsKeyPress,
	)

	altview2Cols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2vertical", altview2Cols.GetOffsets())
	}))

	altview2PileAndKeys := appkeys.New(
		assignTo(&altview2Pile,
			resizable.NewPile([]gowid.IContainerWidget{
				&gowid.ContainerWidget{
					IWidget: packetListViewWithKeys,
					D:       weight(1),
				},
				&gowid.ContainerWidget{
					IWidget: divider.NewUnicode(),
					D:       flow,
				},
				&gowid.ContainerWidget{
					IWidget: altview2ColsAndKeys,
					D:       weight(1),
				},
			}),
		),
		altview2PileKeyPress,
	)

	altview2Pile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2horizontal", altview2Pile.GetOffsets())
	}))

	altview2OuterRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: altview2PileAndKeys,
			D:       weight(1),
		},
	})

	//======================================================================

	maxViewPath = []interface{}{2, 0} // list, structure or hex - whichever one is selected

	mainviewPaths = [][]interface{}{
		{2}, // packet list
		{4}, // packet structure
		{6}, // packet hex
	}

	altview1Paths = [][]interface{}{
		{2, 0, 0}, // packet list
		{2, 0, 2}, // packet structure
		{2, 2},    // packet hex
	}

	altview2Paths = [][]interface{}{
		{2, 0},    // packet list
		{2, 2, 0}, // packet structure
		{2, 2, 2}, // packet hex
	}

	filterPathMain = []interface{}{1, 0, 1}
	filterPathAlt = []interface{}{1, 0, 1}
	filterPathMax = []interface{}{1, 0, 1}

	searchPathMain = []interface{}{1, 2, 6} // 6 is the index of the filter in the search widget
	searchPathAlt = []interface{}{1, 2, 6}
	searchPathMax = []interface{}{1, 2, 6}

	mainview = mainviewRows
	altview1 = altview1OuterRows
	altview2 = altview2OuterRows

	mainViewNoKeys = holder.New(mainview)
	defaultLayout := profiles.ConfString("main.layout", "")
	switch defaultLayout {
	case "altview1":
		mainViewNoKeys = holder.New(altview1)
	case "altview2":
		mainViewNoKeys = holder.New(altview2)
	}

	// <<generalmenu3>>
	menuPathMain = []interface{}{0, 7}
	menuPathAlt = []interface{}{0, 7}
	menuPathMax = []interface{}{0, 7}

	buildStreamUi()
	buildFilterConvsMenu()
	buildNamesMenu(app)
	buildFieldsMenu(app)

	mainView = appkeys.New(
		appkeys.New(
			appkeys.New(
				mainViewNoKeys,
				mainKeyPress, // applied after mainViewNoKeys processes the input
			),
			vimKeysMainView,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		searchPacketsMainView,
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	//======================================================================

	palette := PaletteSwitcher{
		P1:        &DarkModePalette,
		P2:        &RegularPalette,
		ChooseOne: &DarkMode,
	}

	appViewWithKeys := &prefixKeyWidget{
		IWidget: appkeys.New(
			assignTo(&appViewNoKeys, holder.New(mainView)),
			appKeyPress,
		),
	}

	// For minibuffer
	mbView = holder.New(appViewWithKeys)

	if !profiles.ConfBool("main.disable-shark-fin", false) {
		Fin = rossshark.New(mbView)

		steerableFin := appkeys.NewMouse(
			appkeys.New(
				Fin,
				func(evk *tcell.EventKey, app gowid.IApp) bool {
					if Fin.Active() {
						switch evk.Key() {
						case tcell.KeyLeft:
							Fin.Dir = rossshark.Backward
						case tcell.KeyRight:
							Fin.Dir = rossshark.Forward
						default:
							Fin.Deactivate()
						}
						return true
					}
					return false
				},
				appkeys.Options{
					ApplyBefore: true,
				},
			),
			func(evm *tcell.EventMouse, app gowid.IApp) bool {
				if Fin.Active() {
					Fin.Deactivate()
					return true
				}
				return false
			},
			appkeys.Options{
				ApplyBefore: true,
			},
		)

		appView = holder.New(steerableFin)
	} else {
		appView = holder.New(mbView)
	}

	// A restriction on the multiMenu is that it only holds one open menu, so using
	// this trick, only one menu can be open at a time per multiMenu variable. So
	// I am making two because all I need at the moment is two levels of menu.
	multiMenu.IMenuCompatible = holder.New(appView)
	multiMenu2.IMenuCompatible = holder.New(multiMenu)

	multiMenu1Opener.under = appView
	multiMenu1Opener.mm = multiMenu
	multiMenu2Opener.under = multiMenu
	multiMenu2Opener.mm = multiMenu2

	var lastMenu gowid.IWidget = multiMenu2
	menus := []gowid.IMenuCompatible{
		// These menus can both be open at the same time, so I have special
		// handling here. I should use a more general method for all menus. The
		// current method only allows one menu to be open at a time.
		filterConvsMenu1,
		filterConvsMenu2,
	}

	for _, w := range menus {
		w.SetSubWidget(lastMenu, app)
		lastMenu = w
	}

	keyMapper = mapkeys.New(lastMenu)
	keyMappings := termshark.LoadKeyMappings()
	for _, km := range keyMappings {
		log.Infof("Applying keymapping %v --> %v", km.From, km.To)
		keyMapper.AddMapping(km.From, km.To, app)
	}

	if err = termshark.LoadGlobalMarks(globalMarksMap); err != nil {
		// Not fatal
		log.Error(err)
	}

	// Create app, etc, but don't init screen which sets ICANON, etc
	app, err = gowid.NewApp(gowid.AppArgs{
		View:                 keyMapper,
		Palette:              palette,
		Log:                  log.StandardLogger(),
		EnableBracketedPaste: true,
		DontActivate:         true,
		Tty:                  tty,
	})

	if err != nil {
		return nil, err
	}

	gowid.SetFocusPath(mainview, mainviewPaths[0], app)
	gowid.SetFocusPath(altview1, altview1Paths[0], app)
	gowid.SetFocusPath(altview2, altview2Paths[0], app)

	if offs, err := termshark.LoadOffsetFromConfig("mainview"); err == nil {
		mainviewRows.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altviewleft"); err == nil {
		altview1Pile.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altviewright"); err == nil {
		altview1Cols.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altview2horizontal"); err == nil {
		altview2Pile.SetOffsets(offs, app)
	}
	if offs, err := termshark.LoadOffsetFromConfig("altview2vertical"); err == nil {
		altview2Cols.SetOffsets(offs, app)
	}

	return app, err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
