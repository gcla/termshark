// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/blang/semver"
	"github.com/gcla/deep"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/cellmod"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/disable"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/keypress"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/progress"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/spinner"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark"
	"github.com/gcla/termshark/modeswap"
	"github.com/gcla/termshark/pcap"
	"github.com/gcla/termshark/pdmltree"
	"github.com/gcla/termshark/psmltable"
	"github.com/gcla/termshark/ui"
	"github.com/gcla/termshark/widgets/appkeys"
	"github.com/gcla/termshark/widgets/copymodetree"
	"github.com/gcla/termshark/widgets/enableselected"
	"github.com/gcla/termshark/widgets/expander"
	"github.com/gcla/termshark/widgets/filter"
	"github.com/gcla/termshark/widgets/hexdumper"
	"github.com/gcla/termshark/widgets/ifwidget"
	"github.com/gcla/termshark/widgets/resizable"
	"github.com/gcla/termshark/widgets/withscrollbar"
	"github.com/gdamore/tcell"
	lru "github.com/hashicorp/golang-lru"
	flags "github.com/jessevdk/go-flags"
	"github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/fsnotify.v1"
)

// TODO - just for debugging
var ensureGoroutinesStopWG sync.WaitGroup

// Global so that we can change the displayed packet in the struct view, etc
// test
var topview *holder.Widget
var yesno *dialog.Widget
var pleaseWait *dialog.Widget
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
var progWidgetIdx int
var mainviewPaths [][]interface{}
var altview1Paths [][]interface{}
var altview2Paths [][]interface{}
var maxViewPath []interface{}
var filterPathMain []interface{}
var filterPathAlt []interface{}
var filterPathMax []interface{}
var view1idx int
var view2idx int
var generalMenu *menu.Widget
var savedMenu *menu.Widget
var filterWidget *filter.Widget
var openMenuSite *menu.SiteWidget
var packetListViewHolder *holder.Widget
var packetListTable *table.BoundedWidget
var packetStructureViewHolder *holder.Widget
var packetHexViewHolder *holder.Widget
var progressHolder *holder.Widget
var loadProgress *progress.Widget
var loadSpinner *spinner.Widget

var nullw *null.Widget                       // empty
var loadingw gowid.IWidget                   // "loading..."
var singlePacketViewMsgHolder *holder.Widget // either empty or "loading..."
var missingMsgw gowid.IWidget                // centered, holding singlePacketViewMsgHolder
var emptyStructViewTimer *time.Ticker
var emptyHexViewTimer *time.Ticker
var fillSpace *fill.Widget
var fillVBar *fill.Widget
var colSpace *gowid.ContainerWidget

var curPacketStructWidget *copymodetree.Widget
var packetHexWidgets *lru.Cache
var packetListView *rowFocusTableWidget

var curExpandedStructNodes pdmltree.ExpandedPaths // a path to each expanded node in the packet, preserved while navigating
var curStructPosition tree.IPos                   // e.g. [0, 2, 1] -> the indices of the expanded nodes
var curPdmlPosition []string                      // e.g. [ , tcp, tcp.srcport ] -> the path from focus to root in the current struct
var curStructWidgetState interface{}              // e.g. {linesFromTop: 1, ...} -> the positioning of the current struct widget

var cacheRequests []pcap.LoadPcapSlice
var cacheRequestsChan chan struct{} // false means started, true means finished
var quitRequestedChan chan struct{}
var loader *pcap.Loader
var scheduler *pcap.Scheduler
var captureFilter string // global for now, might make it possible to change in app at some point
var tmplData map[string]interface{}
var darkModeSwitchSet bool   // whether switch was passed at command line
var darkModeSwitch bool      // set via command line
var darkMode bool            // global state in app
var autoScrollSwitchSet bool // whether switch was passed at command line
var autoScrollSwitch bool    // set via command line
var autoScroll bool          // true if the packet list should auto-scroll when listening on an interface.
var newPacketsArrived bool   // true if current updates are due to new packets when listening on an interface.
var uiRunning bool           // true if gowid/tcell is controlling the terminal

var fixed gowid.RenderFixed
var flow gowid.RenderFlow
var hmiddle gowid.HAlignMiddle
var vmiddle gowid.VAlignMiddle

var (
	lightGray   gowid.GrayColor = gowid.MakeGrayColor("g74")
	mediumGray  gowid.GrayColor = gowid.MakeGrayColor("g50")
	darkGray    gowid.GrayColor = gowid.MakeGrayColor("g35")
	brightBlue  gowid.RGBColor  = gowid.MakeRGBColor("#08f")
	brightGreen gowid.RGBColor  = gowid.MakeRGBColor("#6f2")

	//======================================================================
	// Regular mode
	//

	//                                                      256 color   < 256 color
	pktListRowSelectedBgReg  *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	pktListRowFocusBgReg     *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	pktListCellSelectedBgReg *modeswap.Color = modeswap.New(darkGray, gowid.ColorBlack)
	pktStructSelectedBgReg   *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	pktStructFocusBgReg      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexTopUnselectedFgReg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	hexTopUnselectedBgReg    *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	hexTopSelectedFgReg      *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	hexTopSelectedBgReg      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexBottomUnselectedFgReg *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexBottomUnselectedBgReg *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	hexBottomSelectedFgReg   *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexBottomSelectedBgReg   *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	hexCurUnselectedFgReg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	hexCurUnselectedBgReg    *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineFgReg             *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineBgReg             *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	filterValidBgReg         *modeswap.Color = modeswap.New(brightGreen, gowid.ColorGreen)

	regularPalette gowid.Palette = gowid.Palette{
		"default":                gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorWhite),
		"title":                  gowid.MakeForeground(gowid.ColorDarkRed),
		"pkt-list-row-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, pktListRowFocusBgReg),
		"pkt-list-cell-focus":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorPurple),
		"pkt-list-row-selected":  gowid.MakePaletteEntry(gowid.ColorWhite, pktListRowSelectedBgReg),
		"pkt-list-cell-selected": gowid.MakePaletteEntry(gowid.ColorWhite, pktListCellSelectedBgReg),
		"pkt-struct-focus":       gowid.MakePaletteEntry(gowid.ColorWhite, pktStructFocusBgReg),
		"pkt-struct-selected":    gowid.MakePaletteEntry(gowid.ColorWhite, pktStructSelectedBgReg),
		"filter-menu-focus":      gowid.MakeStyledPaletteEntry(gowid.ColorBlack, gowid.ColorWhite, gowid.StyleBold),
		"filter-valid":           gowid.MakePaletteEntry(gowid.ColorBlack, filterValidBgReg),
		"filter-invalid":         gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorRed),
		"filter-intermediate":    gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorOrange),
		"dialog":                 gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"dialog-buttons":         gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"button":                 gowid.MakeForeground(gowid.ColorMagenta),
		"button-focus":           gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"progress-default":       gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"progress-complete":      gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(gowid.ColorMagenta)),
		"progress-spinner":       gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"hex-cur-selected":       gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"hex-cur-unselected":     gowid.MakePaletteEntry(hexCurUnselectedFgReg, hexCurUnselectedBgReg),
		"hex-top-selected":       gowid.MakePaletteEntry(hexTopSelectedFgReg, hexTopSelectedBgReg),
		"hex-top-unselected":     gowid.MakePaletteEntry(hexTopUnselectedFgReg, hexTopUnselectedBgReg),
		"hex-bottom-selected":    gowid.MakePaletteEntry(hexBottomSelectedFgReg, hexBottomSelectedBgReg),
		"hex-bottom-unselected":  gowid.MakePaletteEntry(hexBottomUnselectedFgReg, hexBottomUnselectedBgReg),
		"hexln-selected":         gowid.MakePaletteEntry(hexLineFgReg, hexLineBgReg),
		"hexln-unselected":       gowid.MakePaletteEntry(hexLineFgReg, hexLineBgReg),
		"copy-mode-indicator":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkRed),
		"copy-mode":              gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
	}

	//======================================================================
	// Dark mode
	//

	//                                                       256 color   < 256 color
	pktListRowSelectedFgDark  *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	pktListRowSelectedBgDark  *modeswap.Color = modeswap.New(darkGray, gowid.ColorWhite)
	pktListRowFocusBgDark     *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	pktListCellSelectedBgDark *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	pktStructSelectedFgDark   *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	pktStructSelectedBgDark   *modeswap.Color = modeswap.New(darkGray, gowid.ColorWhite)
	pktStructFocusBgDark      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexTopUnselectedFgDark    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlue)
	hexTopUnselectedBgDark    *modeswap.Color = modeswap.New(mediumGray, gowid.ColorWhite)
	hexTopSelectedFgDark      *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	hexTopSelectedBgDark      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexBottomUnselectedFgDark *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorBlack)
	hexBottomUnselectedBgDark *modeswap.Color = modeswap.New(darkGray, gowid.ColorWhite)
	hexBottomSelectedFgDark   *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorBlack)
	hexBottomSelectedBgDark   *modeswap.Color = modeswap.New(darkGray, gowid.ColorWhite)
	hexCurUnselectedFgDark    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorMagenta)
	hexCurUnselectedBgDark    *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineFgDark             *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineBgDark             *modeswap.Color = modeswap.New(darkGray, gowid.ColorBlack)
	filterValidBgDark         *modeswap.Color = modeswap.New(brightGreen, gowid.ColorGreen)
	buttonBgDark              *modeswap.Color = modeswap.New(mediumGray, gowid.ColorWhite)

	darkModePalette gowid.Palette = gowid.Palette{
		"default":                gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorBlack),
		"title":                  gowid.MakeForeground(gowid.ColorRed),
		"pkt-list-row-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, pktListRowFocusBgDark),
		"pkt-list-cell-focus":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorPurple),
		"pkt-list-row-selected":  gowid.MakePaletteEntry(pktListRowSelectedFgDark, pktListRowSelectedBgDark),
		"pkt-list-cell-selected": gowid.MakePaletteEntry(gowid.ColorWhite, pktListCellSelectedBgDark),
		"pkt-struct-focus":       gowid.MakePaletteEntry(gowid.ColorWhite, pktStructFocusBgDark),
		"pkt-struct-selected":    gowid.MakePaletteEntry(pktStructSelectedFgDark, pktStructSelectedBgDark),
		"filter-menu-focus":      gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"filter-valid":           gowid.MakePaletteEntry(gowid.ColorBlack, filterValidBgDark),
		"filter-invalid":         gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorRed),
		"filter-intermediate":    gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorOrange),
		"dialog":                 gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"dialog-buttons":         gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"button":                 gowid.MakePaletteEntry(gowid.ColorMagenta, buttonBgDark),
		"button-focus":           gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"progress-default":       gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"progress-complete":      gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(gowid.ColorMagenta)),
		"progress-spinner":       gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"hex-cur-selected":       gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"hex-cur-unselected":     gowid.MakePaletteEntry(hexCurUnselectedFgDark, hexCurUnselectedBgDark),
		"hex-top-selected":       gowid.MakePaletteEntry(hexTopSelectedFgDark, hexTopSelectedBgDark),
		"hex-top-unselected":     gowid.MakePaletteEntry(hexTopUnselectedFgDark, hexTopUnselectedBgDark),
		"hex-bottom-selected":    gowid.MakePaletteEntry(hexBottomSelectedFgDark, hexBottomSelectedBgDark),
		"hex-bottom-unselected":  gowid.MakePaletteEntry(hexBottomUnselectedFgDark, hexBottomUnselectedBgDark),
		"hexln-selected":         gowid.MakePaletteEntry(hexLineFgDark, hexLineBgDark),
		"hexln-unselected":       gowid.MakePaletteEntry(hexLineFgDark, hexLineBgDark),
		"copy-mode-indicator":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkRed),
		"copy-mode":              gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
	}

	termsharkTemplates = template.Must(template.New("Help").Parse(`
{{define "NameVer"}}termshark {{.Version}}{{end}}

{{define "OneLine"}}A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.{{end}}

{{define "Header"}}{{template "NameVer" .}}

{{template "OneLine"}}
See https://termshark.io for more information.{{end}}

{{define "Footer"}}
If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command- line flags. You can provide
tshark-specific flags and they will be passed through to tshark (-n, -d, -T,
etc). For example:

$ termshark -r file.pcap -T psml -n | less{{end}}

{{define "UIUserGuide"}}{{.UserGuideURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIFAQ"}}{{.FAQURL}}

{{.CopyCommandMessage}}{{end}}

{{define "UIHelp"}}{{template "NameVer" .}}

A wireshark-inspired tui for tshark. Analyze network traffic interactively from your terminal.

'/'   - Go to display filter
'q'   - Quit
'tab' - Switch panes
'c'   - Switch to copy-mode
'|'   - Cycle through pane layouts
'\'   - Toggle pane zoom
'esc' - Activate menu
't'   - In bytes view, switch hex ⟷ ascii
'+/-' - Adjust horizontal split
'</>' - Adjust vertical split
'?'   - Display help

In the filter, type a wireshark display filter expression.

Most terminals will support using the mouse! Try clicking the Close button.

Use shift-left-mouse to copy and shift-right-mouse to paste.{{end}}

{{define "CopyModeHelp"}}{{template "NameVer" .}}

termshark is in copy-mode. You can press:

'q', 'c' - Exit copy-mode
ctrl-c   - Copy from selected widget
left     - Widen selection
right    - Narrow selection{{end}}
'?'      - Display copy-mode help
`))

	// Used to determine if we should run tshark instead e.g. stdout is not a tty
	tsopts struct {
		PassThru    string `long:"pass-thru" default:"auto" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"auto" choice:"true" choice:"false" description:"Run tshark instead (auto => if stdout is not a tty)."`
		PrintIfaces bool   `short:"D" optional:"true" optional-value:"true" description:"Print a list of the interfaces on which termshark can capture."`
	}

	// Termshark's own command line arguments. Used if we don't pass through to tshark.
	opts struct {
		Iface         string         `value-name:"<interface>" short:"i" description:"Interface to read."`
		Pcap          flags.Filename `value-name:"<file>" short:"r" description:"Pcap file to read."`
		DecodeAs      []string       `short:"d" description:"Specify dissection of layer type." value-name:"<layer type>==<selector>,<decode-as protocol>"`
		PrintIfaces   bool           `short:"D" optional:"true" optional-value:"true" description:"Print a list of the interfaces on which termshark can capture."`
		DisplayFilter string         `short:"Y" description:"Apply display filter." value-name:"<displaY filter>"`
		CaptureFilter string         `short:"f" description:"Apply capture filter." value-name:"<capture filter>"`
		PassThru      string         `long:"pass-thru" default:"auto" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"auto" choice:"true" choice:"false" description:"Run tshark instead (auto => if stdout is not a tty)."`
		LogTty        string         `long:"log-tty" default:"false" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"true" choice:"false" description:"Log to the terminal.."`
		DarkMode      func(bool)     `long:"dark-mode" optional:"true" optional-value:"true" description:"Use dark-mode."`
		AutoScroll    func(bool)     `long:"auto-scroll" optional:"true" optional-value:"true" description:"Automatically scroll during live capture."`
		Help          bool           `long:"help" short:"h" optional:"true" optional-value:"true" description:"Show this help message."`
		Version       bool           `long:"version" short:"v" optional:"true" optional-value:"true" description:"Show version information."`

		Args struct {
			FilterOrFile string `value-name:"<filter-or-file>" description:"Filter (capture for iface, display for pcap), or pcap file to read."`
		} `positional-args:"yes"`
	}

	// If args are passed through to tshark (e.g. stdout not a tty), then
	// strip these out so tshark doesn't fail.
	termsharkOnly = []string{"--pass-thru", "--log-tty"}
)

func flagIsTrue(val string) bool {
	return val == "true" || val == "yes"
}

//======================================================================

func init() {
	tmplData = map[string]interface{}{
		"Version":      termshark.Version,
		"FAQURL":       termshark.FAQURL,
		"UserGuideURL": termshark.UserGuideURL,
	}
	quitRequestedChan = make(chan struct{}, 1) // buffered because send happens from ui goroutine, which runs global select
	cacheRequestsChan = make(chan struct{}, 1000)
	cacheRequests = make([]pcap.LoadPcapSlice, 0)
	curExpandedStructNodes = make(pdmltree.ExpandedPaths, 0, 20)
	opts.DarkMode = func(val bool) {
		darkModeSwitch = val
		darkModeSwitchSet = true
	}
	opts.AutoScroll = func(val bool) {
		autoScrollSwitch = val
		autoScrollSwitchSet = true
	}
}

//======================================================================

func writeHelp(p *flags.Parser, w io.Writer) {
	if err := termsharkTemplates.ExecuteTemplate(w, "Header", tmplData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
	p.WriteHelp(w)

	if err := termsharkTemplates.ExecuteTemplate(w, "Footer", tmplData); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

func writeVersion(p *flags.Parser, w io.Writer) {
	if err := termsharkTemplates.ExecuteTemplate(w, "NameVer", tmplData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
}

//======================================================================

func updateProgressBarForInterface(c *pcap.Loader, app gowid.IApp) {
	setProgressIndeterminate(app)
	switch loader.State() {
	case 0:
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			clearProgressWidget(app)
		}))
	default:
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			loadSpinner.Update()
			setProgressWidget(app)
		}))
	}
}

func updateProgressBarForFile(c *pcap.Loader, prevRatio float64, app gowid.IApp) float64 {
	setProgressDeterminate(app)

	psmlProg := Prog{100, 100}
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
	// view into the list of packets will be populated.
	currentRow := -1
	var currentRowMod int64 = -1
	var currentRowDiv int = -1
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			foo, ok := packetListView.Model().RowIdentifier(fxy.Row)
			if ok {
				currentRow = int(foo)
				currentRowMod = int64(currentRow % 1000)
				currentRowDiv = (currentRow / 1000) * 1000
				c.Lock()
				curRowProg.cur, curRowProg.max = int64(currentRow), int64(len(c.PacketPsmlData))
				c.Unlock()
			}
		}
	}

	// Progress determined by how many of the (up to) 1000 pdml packets are read
	// If it's not the same chunk of rows, assume it won't affect our view, so no progress needed
	if c.State()&pcap.LoadingPdml != 0 {
		if c.RowCurrentlyLoading == currentRowDiv {
			if x, err = c.LengthOfPdmlCacheEntry(c.RowCurrentlyLoading); err == nil {
				pdmlPacketProg.cur = int64(x)
				pdmlPacketProg.max = int64(c.KillAfterReadingThisMany)
				if currentRow != -1 && currentRowMod < pdmlPacketProg.max {
					pdmlPacketProg.max = currentRowMod + 1 // zero-based
				}
			}

			// Progress determined by how far through the pcap the pdml reader is.
			c.Lock()
			c2, m, err = termshark.ProcessProgress(termshark.SafePid(c.PdmlCmd), c.PcapPdml)
			c.Unlock()
			if err == nil {
				pdmlIdxProg.cur, pdmlIdxProg.max = c2, m
				if currentRow != -1 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}

			// Progress determined by how many of the (up to) 1000 pcap packets are read
			if x, err = c.LengthOfPcapCacheEntry(c.RowCurrentlyLoading); err == nil {
				pcapPacketProg.cur = int64(x)
				pcapPacketProg.max = int64(c.KillAfterReadingThisMany)
				if currentRow != -1 && currentRowMod < pcapPacketProg.max {
					pcapPacketProg.max = currentRowMod + 1 // zero-based
				}
			}

			// Progress determined by how far through the pcap the pcap reader is.
			c.Lock()
			c2, m, err = termshark.ProcessProgress(termshark.SafePid(c.PcapCmd), c.PcapPcap)
			c.Unlock()
			if err == nil {
				pcapIdxProg.cur, pcapIdxProg.max = c2, m
				if currentRow != -1 {
					// Only need to look this far into the psml file before my view is populated
					m = m * (curRowProg.cur / curRowProg.max)
				}
			}
		}
	}

	if psml, ok := c.PcapPsml.(string); ok && c.State()&pcap.LoadingPsml != 0 {
		c.Lock()
		c2, m, err = termshark.ProcessProgress(termshark.SafePid(c.PsmlCmd), psml)
		c.Unlock()
		if err == nil {
			psmlProg.cur, psmlProg.max = c2, m
		}
	}

	var prog Prog

	// state is guaranteed not to include pcap.Loadingiface if we showing a determinate progress bar
	switch c.State() {
	case pcap.LoadingPsml:
		prog = psmlProg
		select {
		case <-c.StartStage2Chan:
		default:
			prog.cur = prog.cur / 2 // temporarily divide in 2. Leave original for case above - so that the 50%
		}
	case pcap.LoadingPdml:
		prog = progMin(
			progMax(pcapPacketProg, pcapIdxProg), // max because the fastest will win and cancel the other
			progMax(pdmlPacketProg, pdmlIdxProg),
		)
	case pcap.LoadingPsml | pcap.LoadingPdml:
		select {
		case <-c.StartStage2Chan:
			prog = progMin( // min because all of these have to complete, so the slowest determines progress
				psmlProg,
				progMin(
					progMax(pcapPacketProg, pcapIdxProg), // max because the fastest will win and cancel the other
					progMax(pdmlPacketProg, pdmlIdxProg),
				),
			)
		default:
			prog = psmlProg
			prog.cur = prog.cur / 2 // temporarily divide in 2. Leave original for case above - so that the 50%
		}
	}

	curRatio := float64(prog.cur) / float64(prog.max)
	if prog.Complete() {
		if prevRatio < 1.0 {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				clearProgressWidget(app)
			}))
		}
	} else {
		if prevRatio < curRatio {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				loadProgress.SetTarget(app, int(prog.max))
				loadProgress.SetProgress(app, int(prog.cur))
				setProgressWidget(app)
			}))
		}
	}
	return curRatio
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

//======================================================================

func swallowMovementKeys(ev *tcell.EventKey, app gowid.IApp) bool {
	res := false
	switch ev.Key() {
	case tcell.KeyDown, tcell.KeyCtrlN, tcell.KeyUp, tcell.KeyCtrlP, tcell.KeyRight, tcell.KeyCtrlF, tcell.KeyLeft, tcell.KeyCtrlB:
		res = true
	}
	return res
}

func swallowMouseScroll(ev *tcell.EventMouse, app gowid.IApp) bool {
	res := false
	switch ev.Buttons() {
	case tcell.WheelDown:
		res = true
	case tcell.WheelUp:
		res = true
	}
	return res
}

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

	inner := wmaker.MakeWidget(pos, tr)
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

		cwidgets = append(cwidgets,
			&gowid.ContainerWidget{
				IWidget: bn,
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

	res = expander.New(
		isselected.New(
			res,
			styled.New(res, gowid.MakePaletteRef("pkt-struct-selected")),
			styled.New(res, gowid.MakePaletteRef("pkt-struct-focus")),
		),
	)

	return res
}

// The widget representing the data at this level in the tree. Simply use what we extract from
// the PDML.
func makeStructNodeWidget(pos tree.IPos, tr tree.IModel) gowid.IWidget {
	return text.New(tr.Leaf())
}

//======================================================================

// I want to have prefered position work on this, but you have to choose a subwidget
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

// rowFocusTableWidget provides a table that highlights the selected row or
// focused row.
type rowFocusTableWidget struct {
	*table.BoundedWidget
}

var _ gowid.IWidget = (*rowFocusTableWidget)(nil)
var _ gowid.IComposite = (*rowFocusTableWidget)(nil)

func (t *rowFocusTableWidget) SubWidget() gowid.IWidget {
	return t.BoundedWidget
}

func (t *rowFocusTableWidget) Rows() int {
	return t.Widget.Model().(table.IBoundedModel).Rows()
}

func (t *rowFocusTableWidget) Up(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		gowid.UserInput(t.Widget, tcell.NewEventKey(tcell.KeyUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) Down(lines int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < lines; i++ {
		gowid.UserInput(t.Widget, tcell.NewEventKey(tcell.KeyDown, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) UpPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		gowid.UserInput(t.Widget, tcell.NewEventKey(tcell.KeyPgUp, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

func (t *rowFocusTableWidget) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	for i := 0; i < num; i++ {
		gowid.UserInput(t.Widget, tcell.NewEventKey(tcell.KeyPgDn, ' ', tcell.ModNone), size, gowid.Focused, app)
	}
}

// list.IWalker
func (t *rowFocusTableWidget) At(lpos list.IWalkerPosition) gowid.IWidget {
	pos := int(lpos.(table.Position))
	w := t.Widget.AtRow(pos)
	if w == nil {
		return nil
	}

	// Composite so it passes through prefered column
	return &selectedComposite{
		Widget: isselected.New(w,
			styled.New(w, gowid.MakePaletteRef("pkt-list-row-selected")),
			styled.New(w, gowid.MakePaletteRef("pkt-list-row-focus")),
		),
	}
}

// Needed for WidgetAt above to work - otherwise t.Table.Focus() is called, table is the receiver,
// then it calls WidgetAt so ours is not used.
func (t *rowFocusTableWidget) Focus() list.IWalkerPosition {
	return table.Focus(t)
}

//======================================================================

func openError(msgt string, app gowid.IApp) {
	// the same, for now
	openMessage(msgt, app)
}

func openMessage(msgt string, app gowid.IApp) {
	maximizer := &dialog.Maximizer{}

	var al gowid.IHAlignment = hmiddle
	if strings.Count(msgt, "\n") > 0 {
		al = gowid.HAlignLeft{}
	}

	var view gowid.IWidget = text.New(msgt, text.Options{
		Align: al,
	})

	view = hpadding.New(
		view,
		hmiddle,
		gowid.RenderFixed{},
	)

	view = framed.NewSpace(view)

	view = appkeys.New(
		view,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			if ev.Rune() == 'z' { // maximize/unmaximize
				if maximizer.Maxed {
					maximizer.Unmaximize(yesno, app)
				} else {
					maximizer.Maximize(yesno, app)
				}
				return true
			}
			return false
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	yesno = dialog.New(
		view,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)

	dialog.OpenExt(yesno, topview, fixed, fixed, app)
}

func openHelp(tmplName string, app gowid.IApp) {
	yesno = dialog.New(framed.NewSpace(text.New(termshark.TemplateToString(termsharkTemplates, tmplName, tmplData))),
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)
	yesno.Open(topview, ratio(0.5), app)
}

func openPleaseWait(app gowid.IApp) {
	pleaseWait.Open(topview, fixed, app)
}

func openCopyChoices(app gowid.IApp) {
	var cc *dialog.Widget
	maximizer := &dialog.Maximizer{}

	clips := app.Clips()

	cws := make([]gowid.IWidget, 0, len(clips))

	copyCmd := termshark.ConfStringSlice(
		"main.copy-command",
		termshark.CopyToClipboard,
	)

	if len(copyCmd) == 0 {
		openError("Config file has an invalid copy-command entry! Please remove it.", app)
		return
	}

	for _, clip := range clips {
		c2 := clip
		lbl := text.New(clip.ClipName() + ":")
		btn := button.NewBare(text.New(clip.ClipValue(), text.Options{
			Wrap:          text.WrapClip,
			ClipIndicator: "...",
		}))

		btn.OnClick(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			cmd := exec.Command(copyCmd[0], copyCmd[1:]...)
			cmd.Stdin = strings.NewReader(c2.ClipValue())
			outBuf := bytes.Buffer{}
			cmd.Stdout = &outBuf

			cc.Close(app)
			app.InCopyMode(false)

			cmdTimeout := termshark.ConfInt("main.copy-command-timeout", 5)
			if err := cmd.Start(); err != nil {
				openError(fmt.Sprintf("Copy command \"%s\" failed: %v", strings.Join(copyCmd, " "), err), app)
				return
			}

			go func() {
				closed := true
				closeme := func() {
					if !closed {
						pleaseWait.Close(app)
						closed = true
					}
				}
				defer app.Run(gowid.RunFunction(func(app gowid.IApp) {
					closeme()
				}))

				done := make(chan error, 1)
				go func() {
					done <- cmd.Wait()
				}()

				tick := time.NewTicker(time.Duration(200) * time.Millisecond)
				defer tick.Stop()
				tchan := time.After(time.Duration(cmdTimeout) * time.Second)

			Loop:
				for {
					select {
					case <-tick.C:
						app.Run(gowid.RunFunction(func(app gowid.IApp) {
							pleaseWaitSpinner.Update()
							if closed {
								openPleaseWait(app)
								closed = false
							}
						}))

					case <-tchan:
						if err := cmd.Process.Kill(); err != nil {
							app.Run(gowid.RunFunction(func(app gowid.IApp) {
								closeme()
								openError(fmt.Sprintf("Timed out, but could not kill copy command: %v", err), app)
							}))
						} else {
							app.Run(gowid.RunFunction(func(app gowid.IApp) {
								closeme()
								openError(fmt.Sprintf("Copy command \"%v\" timed out", strings.Join(copyCmd, " ")), app)
							}))
						}
						break Loop

					case err := <-done:
						if err != nil {
							app.Run(gowid.RunFunction(func(app gowid.IApp) {
								closeme()
								openError(fmt.Sprintf("Copy command \"%v\" failed: %v", strings.Join(copyCmd, " "), err), app)
							}))
						} else {
							outStr := outBuf.String()
							if len(outStr) == 0 {
								app.Run(gowid.RunFunction(func(app gowid.IApp) {
									closeme()
									openMessage("   Copied!   ", app)
								}))
							} else {
								app.Run(gowid.RunFunction(func(app gowid.IApp) {
									closeme()
									openMessage(fmt.Sprintf("Copied! Output was:\n%s\n", outStr), app)
								}))
							}
						}
						break Loop
					}
				}

			}()

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

	view1 = appkeys.New(
		view1,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			if ev.Rune() == 'z' { // maximize/unmaximize
				if maximizer.Maxed {
					maximizer.Unmaximize(cc, app)
				} else {
					maximizer.Maximize(cc, app)
				}
				return true
			}
			return false
		},
	)

	cc = dialog.New(view1,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)

	cc.OnOpenClose(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
		if !cc.IsOpen() {
			app.InCopyMode(false)
		}
	})))

	dialog.OpenExt(cc, topview, ratio(0.5), ratio(0.8), app)
}

func reallyQuit(app gowid.IApp) {
	msgt := "Do you want to quit?"
	msg := text.New(msgt)
	yesno = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: func(app gowid.IApp, widget gowid.IWidget) {
						quitRequestedChan <- struct{}{}
					},
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)
	yesno.Open(topview, units(len(msgt)+20), app)
}

//======================================================================

type noHandlers struct{}

//======================================================================

type updatePacketViews struct {
	ld  *pcap.Scheduler
	app gowid.IApp
}

var _ pcap.IOnError = updatePacketViews{}
var _ pcap.IClear = updatePacketViews{}
var _ pcap.IBeforeBegin = updatePacketViews{}
var _ pcap.IAfterEnd = updatePacketViews{}

func makePacketViewUpdater(app gowid.IApp) updatePacketViews {
	res := updatePacketViews{}
	res.app = app
	res.ld = scheduler
	return res
}

func (t updatePacketViews) EnableOperations() {
	t.ld.Enable()
}

func (t updatePacketViews) OnClear(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		clearPacketViews(app)
	}))
}

func (t updatePacketViews) BeforeBegin(ch chan<- struct{}) {
	ch2 := loader.PsmlFinishedChan

	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		clearPacketViews(app)
		t.ld.Lock()
		defer t.ld.Unlock()
		setPacketListWidgets(t.ld.PacketPsmlHeaders, t.ld.PacketPsmlData, app)
		setProgressWidget(app)

		// Start this after widgets have been cleared, to get focus change
		termshark.TrackedGo(func() {
			fn2 := func() {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					loader.Lock()
					defer loader.Unlock()
					updatePacketListWithData(loader.PacketPsmlHeaders, loader.PacketPsmlData, app)
				}))
			}

			termshark.RunOnDoubleTicker(ch2, fn2,
				time.Duration(100)*time.Millisecond,
				time.Duration(2000)*time.Millisecond,
				10)
		})

		close(ch)
	}))
}

func (t updatePacketViews) AfterEnd(ch chan<- struct{}) {
	close(ch)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		t.ld.Lock()
		defer t.ld.Unlock()
		updatePacketListWithData(t.ld.PacketPsmlHeaders, t.ld.PacketPsmlData, app)
	}))
}

func (t updatePacketViews) OnError(err error, closeMe chan<- struct{}) {
	close(closeMe)
	log.Error(err)
	if !uiRunning {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		quitRequestedChan <- struct{}{}
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
			openError(errstr, app)
		}))
	}
}

//======================================================================

func reallyClear(app gowid.IApp) {
	msgt := "Do you want to clear current capture?"
	msg := text.New(msgt)
	yesno = dialog.New(
		framed.NewSpace(hpadding.New(msg, hmiddle, fixed)),
		dialog.Options{
			Buttons: []dialog.Button{
				dialog.Button{
					Msg: "Ok",
					Action: func(app gowid.IApp, w gowid.IWidget) {
						yesno.Close(app)
						scheduler.RequestClearPcap(makePacketViewUpdater(app))
					},
				},
				dialog.Cancel,
			},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)
	yesno.Open(topview, units(len(msgt)+28), app)
}

//======================================================================

type simpleMenuItem struct {
	Txt string
	Key gowid.Key
	CB  gowid.WidgetChangedFunction
}

func makeRecentMenu(items []simpleMenuItem) gowid.IWidget {
	menu1Widgets := make([]gowid.IWidget, 0)
	menu1HotKeys := make([]gowid.IWidget, 0)

	max := 0
	for _, w := range items {
		k := fmt.Sprintf("%v", w.Key)
		if len(k) > max {
			max = len(k)
		}
	}

	for _, w := range items {
		load1B := button.NewBare(text.New(w.Txt))
		load1K := button.NewBare(text.New(fmt.Sprintf("%v", w.Key)))
		load1CB := gowid.MakeWidgetCallback("cb", w.CB)
		load1B.OnClick(load1CB)
		if w.Key != gowid.MakeKey(' ') {
			load1K.OnClick(load1CB)
		}
		menu1Widgets = append(menu1Widgets, load1B)
		menu1HotKeys = append(menu1HotKeys, load1K)
	}
	for i, w := range menu1Widgets {
		menu1Widgets[i] = styled.NewInvertedFocus(selectable.New(w), gowid.MakePaletteRef("default"))
	}
	for i, w := range menu1HotKeys {
		menu1HotKeys[i] = styled.NewInvertedFocus(w, gowid.MakePaletteRef("default"))
	}

	menu1Widgets2 := make([]*columns.Widget, len(menu1Widgets))
	for i, w := range menu1Widgets {
		menu1Widgets2[i] = columns.New(
			[]gowid.IContainerWidget{
				&gowid.ContainerWidget{
					IWidget: hpadding.New(
						// size is translated from flowwith{20} to fixed; fixed gives size 6, flowwith aligns right to 12
						hpadding.New(
							selectable.NewUnselectable( // don't want to be able to navigate to the hotkey itself
								menu1HotKeys[i],
							),
							gowid.HAlignRight{},
							fixed,
						),
						gowid.HAlignLeft{},
						gowid.RenderFlowWith{C: max},
					),
					D: fixed,
				},
				&gowid.ContainerWidget{
					IWidget: text.New("| "),
					D:       fixed,
				},
				&gowid.ContainerWidget{
					IWidget: w,
					D:       fixed,
				},
			},
			columns.Options{
				StartColumn: 2,
			},
		)
	}

	menu1cwidgets := make([]gowid.IContainerWidget, len(menu1Widgets2))
	for i, w := range menu1Widgets2 {
		menu1cwidgets[i] = &gowid.ContainerWidget{
			IWidget: w,
			D:       fixed,
		}
	}

	keys := make([]gowid.IKey, 0)
	for _, i := range items {
		if i.Key != gowid.MakeKey(' ') {
			keys = append(keys, i.Key)
		}
	}

	menuListBox1 := keypress.New(
		cellmod.Opaque(
			styled.New(
				framed.NewUnicode(
					pile.New(menu1cwidgets, pile.Options{
						Wrap: true,
					}),
				),
				gowid.MakePaletteRef("default"),
			),
		),
		keypress.Options{
			Keys: keys,
		},
	)

	menuListBox1.OnKeyPress(keypress.MakeCallback("key1", func(app gowid.IApp, w gowid.IWidget, k gowid.IKey) {
		for _, r := range items {
			if gowid.KeysEqual(k, r.Key) && r.Key != gowid.MakeKey(' ') {
				r.CB(app, w)
				break
			}
		}
	}))

	return menuListBox1
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

func copyModeKeys(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	if app.InCopyMode() {
		handled = true

		switch evk.Key() {
		case tcell.KeyRune:
			switch evk.Rune() {
			case 'q', 'c':
				app.InCopyMode(false)
			case '?':
				openHelp("CopyModeHelp", app)
			}
		case tcell.KeyEscape:
			app.InCopyMode(false)
		case tcell.KeyCtrlC:
			openCopyChoices(app)
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
	} else {
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

func appKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Key() == tcell.KeyCtrlC {
		if loader.State()&pcap.LoadingPsml != 0 {
			scheduler.RequestStopLoad(noHandlers{}) // iface and psml
		} else {
			reallyQuit(app)
		}
	} else if evk.Key() == tcell.KeyCtrlL {
		app.Sync()
	} else if evk.Rune() == 'q' || evk.Rune() == 'Q' {
		reallyQuit(app)
	} else if evk.Key() == tcell.KeyTAB {
		if topview.SubWidget() == viewOnlyPacketList {
			topview.SetSubWidget(viewOnlyPacketStructure, app)
		} else if topview.SubWidget() == viewOnlyPacketStructure {
			topview.SetSubWidget(viewOnlyPacketHex, app)
		} else if topview.SubWidget() == viewOnlyPacketHex {
			topview.SetSubWidget(viewOnlyPacketList, app)
		}

		gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
		gowid.SetFocusPath(viewOnlyPacketStructure, maxViewPath, app)
		gowid.SetFocusPath(viewOnlyPacketHex, maxViewPath, app)

		if packetStructureViewHolder.SubWidget() == missingMsgw {
			gowid.SetFocusPath(mainview, mainviewPaths[0], app)
			gowid.SetFocusPath(altview1, altview1Paths[0], app)
			gowid.SetFocusPath(altview2, altview2Paths[0], app)
		} else {
			newidx := -1
			if topview.SubWidget() == mainview {
				v1p := gowid.FocusPath(mainview)
				if deep.Equal(v1p, mainviewPaths[0]) == nil {
					newidx = 1
				} else if deep.Equal(v1p, mainviewPaths[1]) == nil {
					newidx = 2
				} else {
					newidx = 0
				}
			} else if topview.SubWidget() == altview1 {
				v2p := gowid.FocusPath(altview1)
				if deep.Equal(v2p, altview1Paths[0]) == nil {
					newidx = 1
				} else if deep.Equal(v2p, altview1Paths[1]) == nil {
					newidx = 2
				} else {
					newidx = 0
				}
			} else if topview.SubWidget() == altview2 {
				v3p := gowid.FocusPath(altview2)
				if deep.Equal(v3p, altview2Paths[0]) == nil {
					newidx = 1
				} else if deep.Equal(v3p, altview2Paths[1]) == nil {
					newidx = 2
				} else {
					newidx = 0
				}
			}

			if newidx != -1 {
				// Keep the views in sync
				gowid.SetFocusPath(mainview, mainviewPaths[newidx], app)
				gowid.SetFocusPath(altview1, altview1Paths[newidx], app)
				gowid.SetFocusPath(altview2, altview2Paths[newidx], app)
			}
		}

	} else if evk.Key() == tcell.KeyEscape {
		generalMenu.Open(openMenuSite, app)
	} else if evk.Rune() == '|' {
		if topview.SubWidget() == mainview {
			topview.SetSubWidget(altview1, app)
		} else if topview.SubWidget() == altview1 {
			topview.SetSubWidget(altview2, app)
			termshark.SetConf("main.layout", "altview1")
			termshark.SetConf("main.layout", "altview2")
		} else {
			topview.SetSubWidget(mainview, app)
			termshark.SetConf("main.layout", "mainview")
		}
	} else if evk.Rune() == '\\' {
		w := topview.SubWidget()
		fp := gowid.FocusPath(w)
		if w == viewOnlyPacketList || w == viewOnlyPacketStructure || w == viewOnlyPacketHex {
			topview.SetSubWidget(mainview, app)
			if deep.Equal(fp, maxViewPath) == nil {
				switch w {
				case viewOnlyPacketList:
					gowid.SetFocusPath(mainview, mainviewPaths[0], app)
				case viewOnlyPacketStructure:
					gowid.SetFocusPath(mainview, mainviewPaths[1], app)
				case viewOnlyPacketHex:
					gowid.SetFocusPath(mainview, mainviewPaths[2], app)
				}
			}
		} else {
			topview.SetSubWidget(viewOnlyPacketList, app)
			if deep.Equal(fp, maxViewPath) == nil {
				gowid.SetFocusPath(viewOnlyPacketList, maxViewPath, app)
			}
		}
	} else if evk.Rune() == '/' {
		gowid.SetFocusPath(mainview, filterPathMain, app)
		gowid.SetFocusPath(altview1, filterPathAlt, app)
		gowid.SetFocusPath(altview2, filterPathAlt, app)
		gowid.SetFocusPath(viewOnlyPacketList, filterPathMax, app)
		gowid.SetFocusPath(viewOnlyPacketStructure, filterPathMax, app)
		gowid.SetFocusPath(viewOnlyPacketHex, filterPathMax, app)
	} else if evk.Rune() == '?' {
		openHelp("UIHelp", app)
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

func isProgressIndeterminate() bool {
	return progressHolder.SubWidget() == loadSpinner
}

func setProgressDeterminate(app gowid.IApp) {
	progressHolder.SetSubWidget(loadProgress, app)
}

func setProgressIndeterminate(app gowid.IApp) {
	progressHolder.SetSubWidget(loadSpinner, app)
}

func clearProgressWidget(app gowid.IApp) {
	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = nullw
	ds[progWidgetIdx] = fixed
	filterCols.SetSubWidgets(sw, app)
	filterCols.SetDimensions(ds, app)
}

func setProgressWidget(app gowid.IApp) {
	stop := button.New(text.New("Stop"))
	stop2 := styled.NewExt(stop, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))

	stop.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		scheduler.RequestStopLoad(noHandlers{})
	}))

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

	ds := filterCols.Dimensions()
	sw := filterCols.SubWidgets()
	sw[progWidgetIdx] = prog2
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
				// The 't' key will switch from hex <-> ascii
				sw1 = enableselected.New(appkeys.New(
					hex,
					hex.OnKey(func(ev *tcell.EventKey) bool {
						return ev.Rune() == 't'
					}).SwitchView,
				))
			}
			str := getStructWidgetToDisplay(row, app)
			if str != nil {
				sw2 = enableselected.New(str)
			}
		}
	}
	if sw1 != nil {
		packetHexViewHolder.SetSubWidget(sw1, app)
		emptyHexViewTimer = nil
	} else {
		if emptyHexViewTimer == nil {
			startEmptyHexViewTimer()
		}
	}
	if sw2 != nil {
		packetStructureViewHolder.SetSubWidget(sw2, app)
		emptyStructViewTimer = nil
	} else {
		if emptyStructViewTimer == nil {
			startEmptyStructViewTimer()
		}
	}

}

func makePacketListModel(packetPsmlHeaders []string, packetPsmlData [][]string, app gowid.IApp) *psmltable.Model {
	packetPsmlTableModel := table.NewSimpleModel(
		packetPsmlHeaders,
		packetPsmlData,
		table.SimpleOptions{
			Style: table.StyleOptions{
				VerticalSeparator:   fill.New(' '),
				HeaderStyleProvided: true,
				HeaderStyleFocus:    gowid.MakePaletteRef("pkt-list-cell-focus"),
				CellStyleProvided:   true,
				CellStyleSelected:   gowid.MakePaletteRef("pkt-list-cell-selected"),
				CellStyleFocus:      gowid.MakePaletteRef("pkt-list-cell-focus"),
			},
			Layout: table.LayoutOptions{
				Widths: []gowid.IWidgetDimension{
					weightupto(6, 10),
					weightupto(10, 14),
					weightupto(14, 32),
					weightupto(14, 32),
					weightupto(12, 32),
					weightupto(8, 8),
					weight(40),
				},
			},
		},
	)

	expandingModel := psmltable.New(packetPsmlTableModel, gowid.MakePaletteRef("pkt-list-row-focus"))
	if len(expandingModel.Comparators) > 0 {
		expandingModel.Comparators[0] = table.IntCompare{}
		expandingModel.Comparators[5] = table.IntCompare{}
	}

	return expandingModel
}

func updatePacketListWithData(packetPsmlHeaders []string, packetPsmlData [][]string, app gowid.IApp) {
	model := makePacketListModel(packetPsmlHeaders, packetPsmlData, app)
	newPacketsArrived = true
	packetListTable.SetModel(model, app)
	newPacketsArrived = false
	if autoScroll {
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
}

func setPacketListWidgets(packetPsmlHeaders []string, packetPsmlData [][]string, app gowid.IApp) {
	expandingModel := makePacketListModel(packetPsmlHeaders, packetPsmlData, app)

	packetListTable = &table.BoundedWidget{Widget: table.New(expandingModel)}
	packetListView = &rowFocusTableWidget{packetListTable}

	packetListView.Lower().IWidget = list.NewBounded(packetListView)
	packetListView.OnFocusChanged(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		fxy, err := packetListView.FocusXY()
		if err != nil {
			return
		}

		if !newPacketsArrived {
			// this focus change must've been user-initiated, so stop auto-scrolling with new packets.
			// This mimics Wireshark's behavior.
			autoScroll = false
		}

		row2 := fxy.Row
		row3, gotrow := packetListView.Model().RowIdentifier(row2)
		row := int(row3)

		if gotrow && row >= 0 {

			rowm := row % 1000

			cacheRequests = cacheRequests[:0]

			cacheRequests = append(cacheRequests, pcap.LoadPcapSlice{
				Row:    (row / 1000) * 1000,
				Cancel: true,
			})
			if rowm > 500 {
				cacheRequests = append(cacheRequests, pcap.LoadPcapSlice{
					Row: ((row / 1000) + 1) * 1000,
				})
			} else {
				row2 := ((row / 1000) - 1) * 1000
				if row2 < 0 {
					row2 = 0
				}
				cacheRequests = append(cacheRequests, pcap.LoadPcapSlice{
					Row: row2,
				})
			}

			cacheRequestsChan <- struct{}{}

			setLowerWidgets(app)
		}
	}))

	withScrollbar := withscrollbar.New(packetListView)
	packetListViewHolder.SetSubWidget(enableselected.New(withScrollbar), app)
}

func expandStructWidgetAtPosition(row int, pos int, app gowid.IApp) {
	if curPacketStructWidget != nil {
		walker := curPacketStructWidget.Walker().(*termshark.NoRootWalker)
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
	treeAtCurPos := curStructPosition.GetSubStructure(tr)
	// Save [/, tcp, tcp.srcport] - so we can apply if user moves in packet list
	curPdmlPosition = treeAtCurPos.(*pdmltree.Model).PathToRoot()
}

func getLayersFromStructWidget(row int, pos int) []hexdumper.LayerStyler {
	layers := make([]hexdumper.LayerStyler, 0)

	row2 := (row / 1000) * 1000
	if ws, ok := loader.PacketCache.Get(row2); ok {
		srcb2 := ws.(pcap.CacheEntry).Pdml
		if row%1000 < len(srcb2) {
			data, err := xml.Marshal(srcb2[row%1000])
			if err != nil {
				log.Fatal(err)
			}

			tr := pdmltree.DecodePacket(data, &curExpandedStructNodes)
			tr.Expanded = true

			layers = tr.HexLayers(pos, false)
		}
	}

	return layers
}

func getHexWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("p%d", row))
}

// Can return nil
func getHexWidgetToDisplay(row int) *hexdumper.Widget {
	var res2 *hexdumper.Widget

	if val, ok := packetHexWidgets.Get(row); ok {
		res2 = val.(*hexdumper.Widget)
	} else {
		row2 := (row / 1000) * 1000
		if ws, ok := loader.PacketCache.Get(row2); ok {
			srca := ws.(pcap.CacheEntry).Pcap
			if len(srca) > row%1000 {
				src := srca[row%1000]
				b := make([]byte, len(src))
				copy(b, src)

				layers := getLayersFromStructWidget(row, 0)
				res2 = hexdumper.New(b, hexdumper.Options{
					StyledLayers:      layers,
					CursorUnselected:  "hex-cur-unselected",
					CursorSelected:    "hex-cur-selected",
					LineNumUnselected: "hexln-unselected",
					LineNumSelected:   "hexln-selected",
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
					if topview.SubWidget() == mainview {
						v1p := gowid.FocusPath(mainview)
						if deep.Equal(v1p, mainviewPaths[2]) != nil { // it's not hex
							return
						}
					} else if topview.SubWidget() == altview1 {
						v2p := gowid.FocusPath(altview1)
						if deep.Equal(v2p, altview1Paths[2]) != nil { // it's not hex
							return
						}
					} else { // altview2
						v3p := gowid.FocusPath(altview2)
						if deep.Equal(v3p, altview2Paths[2]) != nil { // it's not hex
							return
						}
					}

					expandStructWidgetAtPosition(row, res2.Position(), app)
				}))

				packetHexWidgets.Add(row, res2)
			}
		}
	}
	return res2
}

//======================================================================

func getStructWidgetKey(row int) []byte {
	return []byte(fmt.Sprintf("s%d", row))
}

// Note - hex can be nil
// Note - returns nil if one can't be found
func getStructWidgetToDisplay(row int, app gowid.IApp) gowid.IWidget {
	var res gowid.IWidget

	row2 := (row / 1000) * 1000
	if ws, ok := loader.PacketCache.Get(row2); ok {
		srca := ws.(pcap.CacheEntry).Pdml
		if len(srca) > row%1000 {
			data, err := xml.Marshal(srca[row%1000])
			if err != nil {
				log.Fatal(err)
			}

			tr := pdmltree.DecodePacket(data, &curExpandedStructNodes)
			tr.Expanded = true

			var pos tree.IPos = tree.NewPos()
			pos = tree.NextPosition(pos, tr) // Start ahead by one, then never go back

			rwalker := tree.NewWalker(tr, pos,
				tree.NewCachingMaker(tree.WidgetMakerFunction(makeStructNodeWidget)),
				tree.NewCachingDecorator(tree.DecoratorFunction(makeStructNodeDecoration)))
			// Without the caching layer, clicking on a button has no effect
			walker := termshark.NewNoRootWalker(rwalker)

			// Send the layers represents the tree expansion to hex.
			// This could be the user clicking inside the tree. Or it might be the position changing
			// in the hex widget, resulting in a callback to programmatically change the tree expansion,
			// which then calls back to the hex
			updateHex := func(app gowid.IApp, twalker tree.ITreeWalker) {
				newhex := getHexWidgetToDisplay(row)
				if newhex != nil {

					newtree := twalker.Tree().(*pdmltree.Model)
					newpos := twalker.Focus().(tree.IPos)

					leaf := newpos.GetSubStructure(twalker.Tree()).(*pdmltree.Model)

					coverWholePacket := false

					// This skips the "frame" node in the pdml that covers the entire range of bytes. If newpos
					// is [0] then the user has chosen that node by interacting with the struct view (the hex view
					// can't choose any position that maps to the first pdml child node) - so in this case, we
					// send back a layer spanning the entire packet. Otherwise we don't want to send back that
					// packet-spanning layer because it will always be the layer returned, meaning the hexdumper
					// will always show the entire packet highlighted.
					if newpos.Equal(tree.NewPosExt([]int{0})) {
						coverWholePacket = true
					}

					newlayers := newtree.HexLayers(leaf.Pos, coverWholePacket)
					if len(newlayers) > 0 {
						newhex.SetLayers(newlayers, app)

						curhexpos := newhex.Position()
						smallestlayer := newlayers[len(newlayers)-1]

						if !(smallestlayer.Start <= curhexpos && curhexpos < smallestlayer.End) {
							// This might trigger a callback from the hex layer since the position is set. Which will call
							// back into here. But then this logic should not be triggered because the new pos will be
							// inside the smallest layer
							newhex.SetPosition(smallestlayer.Start, app)
						}
					}
				}

			}

			tb := copymodetree.New(tree.New(walker), copyModePalette{})
			res = tb
			// Save this in case the hex layer needs to change it
			curPacketStructWidget = tb

			// if not nil, it means the user has interacted with some struct widget at least once causing
			// a focus change. We track the current focus e.g. [0, 2, 1] - the indices through the tree leading
			// to the focused item. We programatically adjust the focus widget of the new struct (e.g. after
			// navigating down one in the packet list), but only if we can move focus to the same PDML field
			// as the old struct. For example, if we are on tcp.srcport in the old packet, and we can
			// open up tcp.srcport in the new packet, then we do so. This is not perfect, because I use the old
			// pdml tre eposition, which is a sequence of integer indices. This means if the next packet has
			// an extra layer before TCP, say some encapsulation, then I could still open up tcp.srcport, but
			// I don't find it because I find the candidate focus widget using the list of integer indices.
			if curStructPosition != nil {

				curPos := curStructPosition                           // e.g. [0, 2, 1]
				treeAtCurPos := curPos.GetSubStructure(walker.Tree()) // e.g. the TCP *pdmltree.Model
				if treeAtCurPos != nil && deep.Equal(curPdmlPosition, treeAtCurPos.(*pdmltree.Model).PathToRoot()) == nil {
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

			} else {
				curStructPosition = walker.Focus().(tree.IPos)
			}

			tb.OnFocusChanged(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
				curStructWidgetState = tb.State()
			})))

			walker.OnFocusChanged(tree.MakeCallback("cb", func(app gowid.IApp, twalker tree.ITreeWalker) {
				updateHex(app, twalker)
				// need to save the position, so it can be applied to the next struct widget
				// if brought into focus by packet list navigation
				curStructPosition = walker.Focus().(tree.IPos)

				updateCurrentPdmlPosition(walker.Tree())
			}))

			// Update hex at the end, having set up callbacks. We want to make sure that
			// navigating around the hext view expands the struct view in such a way as to
			// preserve these changes when navigating the packet view
			updateHex(app, walker)

		}
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

type saveRecents struct {
	updatePacketViews
	pcap   string
	filter string
}

var _ pcap.IAfterEnd = saveRecents{}

func (t saveRecents) AfterEnd(closeMe chan<- struct{}) {
	t.updatePacketViews.AfterEnd(closeMe)
	if t.pcap != "" {
		termshark.AddToRecentFiles(t.pcap)
	}
	if t.filter != "" {
		termshark.AddToRecentFilters(t.filter)
	}
}

// Call from app goroutine context
func requestLoadPcapWithCheck(pcap string, displayFilter string, app gowid.IApp) {
	if _, err := os.Stat(pcap); os.IsNotExist(err) {
		openError(fmt.Sprintf("File %s not found.", pcap), app)
	} else {
		scheduler.RequestLoadPcap(pcap, displayFilter, saveRecents{makePacketViewUpdater(app), pcap, displayFilter})
	}
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

func makeRecentMenuWidget() gowid.IWidget {
	savedItems := make([]simpleMenuItem, 0)
	cfiles := termshark.ConfStringSlice("main.recent-files", []string{})
	if cfiles != nil {
		for i, s := range cfiles {
			scopy := s
			savedItems = append(savedItems,
				simpleMenuItem{
					Txt: s,
					Key: gowid.MakeKey('a' + rune(i)),
					CB: func(app gowid.IApp, w gowid.IWidget) {
						savedMenu.Close(app)
						// capFilter global, set up in cmain()
						requestLoadPcapWithCheck(scopy, filterWidget.Value(), app)
					},
				},
			)
		}
	}
	savedListBox := makeRecentMenu(savedItems)

	return savedListBox
}

//======================================================================

type savedCompleterCallback struct {
	prefix string
	comp   termshark.IPrefixCompleterCallback
}

var _ termshark.IPrefixCompleterCallback = (*savedCompleterCallback)(nil)

func (s *savedCompleterCallback) Call(orig []string) {
	if s.prefix == "" {
		comps := termshark.ConfStrings("main.recent-filters")
		if len(comps) == 0 {
			comps = orig
		}
		s.comp.Call(comps)
	} else {
		s.comp.Call(orig)
	}
}

type savedCompleter struct {
	def termshark.IPrefixCompleter
}

var _ termshark.IPrefixCompleter = (*savedCompleter)(nil)

func (s savedCompleter) Completions(prefix string, cb termshark.IPrefixCompleterCallback) {
	ncomp := &savedCompleterCallback{
		prefix: prefix,
		comp:   cb,
	}
	s.def.Completions(prefix, ncomp)
}

//======================================================================

type setStructWidgets struct {
	ld  *pcap.Loader
	app gowid.IApp
}

var _ pcap.IOnError = setStructWidgets{}
var _ pcap.IClear = setStructWidgets{}
var _ pcap.IBeforeBegin = setStructWidgets{}
var _ pcap.IAfterEnd = setStructWidgets{}

func (s setStructWidgets) OnClear(closeMe chan<- struct{}) {
	close(closeMe)
}

func (s setStructWidgets) BeforeBegin(ch chan<- struct{}) {
	s2ch := loader.Stage2FinishedChan

	termshark.TrackedGo(func() {
		fn2 := func() {
			s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
				setLowerWidgets(app)
			}))
		}

		termshark.RunOnDoubleTicker(s2ch, fn2,
			time.Duration(100)*time.Millisecond,
			time.Duration(2000)*time.Millisecond,
			10)
	})

	close(ch)
}

// Close the channel before the callback. When the global loader state is idle,
// app.Quit() will stop accepting app callbacks, so the goroutine that waits
// for ch to be closed will never terminate.
func (s setStructWidgets) AfterEnd(ch chan<- struct{}) {
	close(ch)
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		setLowerWidgets(app)
		singlePacketViewMsgHolder.SetSubWidget(nullw, app)
	}))
}

func (s setStructWidgets) OnError(err error, closeMe chan<- struct{}) {
	close(closeMe)
	log.Error(err)
	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		openError(fmt.Sprintf("%v", err), app)
	}))
}

//======================================================================

func startEmptyStructViewTimer() {
	emptyStructViewTimer = time.NewTicker(time.Duration(500) * time.Millisecond)
}

func startEmptyHexViewTimer() {
	emptyHexViewTimer = time.NewTicker(time.Duration(500) * time.Millisecond)
}

//======================================================================

type setNewPdmlRequests struct {
	*pcap.Scheduler
}

var _ pcap.ICacheUpdater = setNewPdmlRequests{}

func (u setNewPdmlRequests) WhenLoadingPdml() {
	u.When(func() bool {
		return u.State()&pcap.LoadingPdml == pcap.LoadingPdml
	}, func() {
		cacheRequestsChan <- struct{}{}
	})
}

func (u setNewPdmlRequests) WhenNotLoadingPdml() {
	u.When(func() bool {
		return u.State()&pcap.LoadingPdml == 0
	}, func() {
		cacheRequestsChan <- struct{}{}
	})
}

//======================================================================

// Run cmain() and afterwards make sure all goroutines stop, then exit with
// the correct exit code. Go's main() prototype does not provide for returning
// a value.
func main() {
	// TODO - fix this later. goroutinewg is used every time a
	// goroutine is started, to ensure we don't terminate until all are
	// stopped. Any exception is a bug.
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

	tsharkBin := termshark.TSharkBin()

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
		(flagIsTrue(tsopts.PassThru) ||
			(tsopts.PassThru == "auto" && !isatty.IsTerminal(os.Stdout.Fd())) ||
			tsopts.PrintIfaces) {

		bin, err := exec.LookPath(tsharkBin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error looking up tshark binary: %v\n", err)
			return 1
		}
		args := []string{}
		for _, arg := range os.Args[1:] {
			if !termshark.StringInSlice(arg, termsharkOnly) && !termshark.StringIsArgPrefixOf(arg, termsharkOnly) {
				args = append(args, arg)
			}
		}
		args = append([]string{bin}, args...)

		if runtime.GOOS != "windows" {
			err = syscall.Exec(bin, args, os.Environ())
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

	// Parse the args now as intended for termshark
	tmFlags := flags.NewParser(&opts, flags.PassDoubleDash)
	var filterArgs []string
	filterArgs, err = tmFlags.Parse()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Command-line error: %v\n\n", err)
		writeHelp(tmFlags, os.Stderr)
		return 1
	}

	if opts.Help {
		writeHelp(tmFlags, os.Stdout)
		return 0
	}

	if opts.Version {
		writeVersion(tmFlags, os.Stdout)
		return 0
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
	captureFilter = opts.CaptureFilter

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
	if !flagIsTrue(opts.LogTty) {
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

	foundTshark := false
	if termshark.ConfString("main.tshark", "") == "" {
		if _, err = os.Stat(tsharkBin); err == nil {
			foundTshark = true
		} else if termshark.IsCommandInPath(tsharkBin) {
			foundTshark = true
		}
		if !foundTshark {
			fmt.Fprintf(os.Stderr, "Could not run tshark binary '%s'. The tshark binary is required to run termshark.\n", tsharkBin)
			fmt.Fprintf(os.Stderr, "Check your config file %s\n", termshark.ConfFile("termshark.toml"))
			return 1
		}
	} else {
		if !termshark.IsCommandInPath(tsharkBin) {
			fmt.Fprintf(os.Stderr, "Could not find tshark in your PATH. The tshark binary is required to run termshark.\n")
			if termshark.IsCommandInPath("apt") {
				fmt.Fprintf(os.Stderr, "Try installing with: apt install tshark")
			} else if termshark.IsCommandInPath("apt-get") {
				fmt.Fprintf(os.Stderr, "Try installing with: apt-get install tshark")
			} else if termshark.IsCommandInPath("yum") {
				fmt.Fprintf(os.Stderr, "Try installing with: yum install wireshark")
			} else if termshark.IsCommandInPath("brew") {
				fmt.Fprintf(os.Stderr, "Try installing with: brew install wireshark")
			} else {
				fmt.Fprintln(os.Stderr, "")
			}
			fmt.Fprintln(os.Stderr, "")
			return 1
		}
		tsharkBin = termshark.DirOfPathCommandUnsafe(tsharkBin)
	}

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
		darkMode = darkModeSwitch
	} else {
		darkMode = termshark.ConfBool("main.dark-mode")
	}

	// Initialize application state for auto-scroll
	if autoScrollSwitchSet {
		autoScroll = autoScrollSwitch
	} else {
		autoScroll = termshark.ConfBool("main.auto-scroll")
	}

	//======================================================================
	//
	// Build the UI

	var app *gowid.App

	widgetCacheSize := termshark.ConfInt("main.ui-cache-size", 1000)
	if widgetCacheSize < 64 {
		widgetCacheSize = 64
	}
	packetHexWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Internal error: %v\n", err)
		return 1
	}

	nullw = null.New()

	loadingw = text.New("Loading, please wait...")
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

	missingMsgw = vpadding.New( // centred
		hpadding.New(singlePacketViewMsgHolder, hmiddle, fixed),
		vmiddle,
		flow,
	)

	pleaseWaitSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})

	pleaseWait = dialog.New(framed.NewSpace(
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
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)

	title := styled.New(text.New(termshark.TemplateToString(termsharkTemplates, "NameVer", tmplData)), gowid.MakePaletteRef("title"))

	copyMode := styled.New(
		ifwidget.New(
			text.New(" COPY-MODE "),
			null.New(),
			func() bool {
				return app != nil && app.InCopyMode()
			},
		),
		gowid.MakePaletteRef("copy-mode-indicator"),
	)

	//======================================================================

	openMenu := button.New(text.New("Misc"))
	openMenu2 := styled.NewExt(openMenu, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))

	openMenuSite = menu.NewSite(menu.SiteOptions{YOffset: 1})
	openMenu.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		generalMenu.Open(openMenuSite, app)
	}))

	//======================================================================

	generalMenuItems := []simpleMenuItem{
		simpleMenuItem{
			Txt: "Help",
			Key: gowid.MakeKey('?'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				generalMenu.Close(app)
				openHelp("UIHelp", app)
			},
		},
		simpleMenuItem{
			Txt: "Clear Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlW, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				generalMenu.Close(app)
				reallyClear(app)
			},
		},
		simpleMenuItem{
			Txt: "Refresh Screen",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlL, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				generalMenu.Close(app)
				app.Sync()
			},
		},
		simpleMenuItem{
			Txt: "Toggle Dark Mode",
			Key: gowid.MakeKey('d'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				generalMenu.Close(app)
				darkMode = !darkMode
				termshark.SetConf("main.dark-mode", darkMode)
			},
		},
		simpleMenuItem{
			Txt: "Quit",
			Key: gowid.MakeKey('q'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				generalMenu.Close(app)
				reallyQuit(app)
			},
		},
	}

	generalMenuListBox := makeRecentMenu(generalMenuItems)

	generalMenu = menu.New("main", generalMenuListBox, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	loadProgress = progress.New(progress.Options{
		Normal:   gowid.MakePaletteRef("progress-default"),
		Complete: gowid.MakePaletteRef("progress-complete"),
	})

	loadSpinner = spinner.New(spinner.Options{
		Styler: gowid.MakePaletteRef("progress-spinner"),
	})

	savedListBox := makeRecentMenuWidget()
	savedListBoxWidgetHolder := holder.New(savedListBox)

	savedMenu = menu.New("saved", savedListBoxWidgetHolder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	titleView := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: title,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: fill.New(' '),
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: copyMode,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: fill.New(' '),
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: openMenuSite,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: openMenu2,
			D:       fixed,
		},
	})

	packetListViewHolder = holder.New(nullw)
	packetStructureViewHolder = holder.New(nullw)
	packetHexViewHolder = holder.New(nullw)

	progressHolder = holder.New(nullw)

	applyw := button.New(text.New("Apply"))
	applyWidget2 := styled.NewExt(applyw, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))
	applyWidget := disable.NewEnabled(applyWidget2)

	filterWidget = filter.New(filter.Options{
		Completer: savedCompleter{def: termshark.NewFields()},
	})

	defer filterWidget.Close()

	applyw.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		scheduler.RequestNewFilter(filterWidget.Value(), saveRecents{
			updatePacketViews: makePacketViewUpdater(app),
			pcap:              "",
			filter:            filterWidget.Value(),
		})
	}))

	filterWidget.OnValid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Enable()
	}))
	filterWidget.OnInvalid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Disable()
	}))
	filterLabel := text.New("Filter: ")

	savedw := button.New(text.New("Recent"))
	savedWidget := styled.NewExt(savedw, gowid.MakePaletteRef("button"), gowid.MakePaletteRef("button-focus"))
	savedBtnSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	savedw.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		savedMenu.Open(savedBtnSite, app)
	}))

	progWidgetIdx = 7 // adjust this if nullw moves position in filterCols
	filterCols = columns.NewFixed(filterLabel,
		&gowid.ContainerWidget{
			IWidget: filterWidget,
			D:       weight(100),
		},
		applyWidget, colSpace, savedBtnSite, savedWidget, colSpace, nullw)

	filterView := framed.NewUnicode(filterCols)

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
				packetListViewHolder,
				appKeysResize1,
			),
			swallowMovementKeys,
		),
		swallowMouseScroll,
	)

	packetStructureViewWithKeys := appkeys.New(
		appkeys.NewMouse(
			appkeys.New(
				appkeys.New(
					packetStructureViewHolder,
					appKeysResize2,
				),
				swallowMovementKeys,
			),
			swallowMouseScroll,
		),
		copyModeKeys, appkeys.Options{
			ApplyBefore: true,
		},
	)

	packetHexViewHolderWithKeys := appkeys.New(
		appkeys.NewMouse(
			appkeys.New(
				packetHexViewHolder,
				swallowMovementKeys,
			),
			swallowMouseScroll,
		),
		copyModeKeys, appkeys.Options{
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
			D:       units(3),
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
			D:       units(3),
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
			D:       units(3),
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
			D:       units(3),
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolder,
			D:       weight(1),
		},
	})

	//======================================================================

	altview1Pile = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: packetListViewHolder,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: divider.NewUnicode(),
			D:       flow,
		},
		&gowid.ContainerWidget{
			IWidget: packetStructureViewHolder,
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
			IWidget: packetHexViewHolder,
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
			D:       units(3),
		},
		&gowid.ContainerWidget{
			IWidget: altview1ColsAndKeys,
			D:       weight(1),
		},
	})

	//======================================================================

	altview2Cols = resizable.NewColumns([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: packetStructureViewHolder,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: fillVBar,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: packetHexViewHolder,
			D:       weight(1),
		},
	})

	altview2Cols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2vertical", altview2Cols.GetOffsets())
	}))

	altview2ColsAndKeys := appkeys.New(altview2Cols, altview2ColsKeyPress)

	altview2Pile = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: packetListViewHolder,
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
	})

	altview2Pile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		termshark.SaveOffsetToConfig("altview2horizontal", altview2Pile.GetOffsets())
	}))

	altview2PileAndKeys := appkeys.New(altview2Pile, altview2PileKeyPress)

	altview2OuterRows = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       units(3),
		},
		&gowid.ContainerWidget{
			IWidget: altview2PileAndKeys,
			D:       weight(1),
		},
	})

	//======================================================================

	maxViewPath = []interface{}{2, 0} // list, structure or hex - whichever one is selected

	mainviewPaths = [][]interface{}{
		{2, 0}, // packet list
		{4},    // packet structure
		{6},    // packet hex
	}

	altview1Paths = [][]interface{}{
		{2, 0, 0, 0}, // packet list
		{2, 0, 2},    // packet structure
		{2, 2},       // packet hex
	}

	altview2Paths = [][]interface{}{
		{2, 0, 0}, // packet list
		{2, 2, 0}, // packet structure
		{2, 2, 2}, // packet hex
	}

	filterPathMain = []interface{}{1, 1}
	filterPathAlt = []interface{}{1, 1}
	filterPathMax = []interface{}{1, 1}

	mainview = mainviewRows
	altview1 = altview1OuterRows
	altview2 = altview2OuterRows

	topview = holder.New(mainview)
	defaultLayout := termshark.ConfString("main.layout", "")
	switch defaultLayout {
	case "altview1":
		topview = holder.New(altview1)
	case "altview2":
		topview = holder.New(altview2)
	}

	keylayer := appkeys.New(topview, appKeyPress)

	palette := termshark.PaletteSwitcher{
		P1:        &darkModePalette,
		P2:        &regularPalette,
		ChooseOne: &darkMode,
	}

	// Set them up here so they have access to any command-line flags that
	// need to be passed to the tshark commands used
	pdmlArgs := termshark.ConfStringSlice("main.pdml-args", []string{})
	psmlArgs := termshark.ConfStringSlice("main.psml-args", []string{})
	tsharkArgs := termshark.ConfStringSlice("main.tshark-args", []string{})
	cacheSize := termshark.ConfInt("main.pcap-cache-size", 64)
	scheduler = pcap.NewScheduler(
		pcap.MakeCommands(opts.DecodeAs, tsharkArgs, pdmlArgs, psmlArgs),
		pcap.Options{
			CacheSize: cacheSize,
		},
	)
	loader = scheduler.Loader

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

	// Create app, etc, but don't init screen which sets ICANON, etc
	app, err = gowid.NewApp(gowid.AppArgs{
		View:         keylayer,
		Palette:      palette,
		DontActivate: true,
		Log:          log.StandardLogger(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if cerr, ok := termshark.RootCause(err).(*exec.Error); ok {
			if cerr.Err.Error() == exec.ErrNotFound.Error() {
				fmt.Fprintf(os.Stderr, "Termshark could not recognize your terminal. Try changing $TERM.\n")
			}
		}
		return 1
	}

	appRunner := app.Runner()

	for _, m := range filterWidget.Menus() {
		app.RegisterMenu(m)
	}
	app.RegisterMenu(savedMenu)
	app.RegisterMenu(generalMenu)

	// Populate the filter widget initially - runs asynchronously
	go filterWidget.UpdateCompletions(app)

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

	uiRunning = false

	validator := filter.Validator{
		Invalid: &filter.ValidateCB{
			App: app,
			Fn: func(app gowid.IApp) {
				if !uiRunning {
					fmt.Fprintf(os.Stderr, "Invalid filter: %s\n", displayFilter)
					quitRequestedChan <- struct{}{}
				} else {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						openError(fmt.Sprintf("Invalid filter: %s", displayFilter), app)
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
				filterWidget.SetValue(displayFilter, app)
			}))
			requestLoadPcapWithCheck(absfile, displayFilter, app)
		}
		validator.Valid = &filter.ValidateCB{Fn: doit, App: app}
		validator.Validate(displayFilter)
		// no auto-scroll when reading a file
		autoScroll = false
	} else if psrc.IsInterface() || psrc.IsFifo() || psrc.IsPipe() {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		ifaceExitCode = 0
		//if ifaceExitCode, ifaceErr = termshark.RunForExitCode("dumpcap", "-i", useIface, "-a", "duration:1", "-w", os.DevNull); ifaceExitCode != 0 {
		//return 1
		//}

		ifValid := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				filterWidget.SetValue(displayFilter, app)
			}))
			ifacePcapFilename = ifaceTmpFile
			scheduler.RequestLoadInterface(psrc, captureFilter, displayFilter, ifaceTmpFile,
				saveRecents{
					updatePacketViews: makePacketViewUpdater(app),
					pcap:              "",
					filter:            displayFilter,
				})
		}
		validator.Valid = &filter.ValidateCB{Fn: ifValid, App: app}
		validator.Validate(displayFilter)
	}

	configChangedFn := func(app gowid.IApp) {
		savedListBox = makeRecentMenuWidget()
		savedListBoxWidgetHolder.SetSubWidget(savedListBox, app)
	}

	quitRequested := false
	prevstate := loader.State()
	var prev float64

	progTicker := time.NewTicker(time.Duration(200) * time.Millisecond)

	loaderPsmlFinChan := loader.PsmlFinishedChan
	loaderIfaceFinChan := loader.IfaceFinishedChan
	loaderPdmlFinChan := loader.Stage2FinishedChan

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

		if emptyStructViewTimer != nil {
			emptyStructViewChan = emptyStructViewTimer.C
		}
		// For setting hex views empty
		if emptyHexViewTimer != nil {
			emptyHexViewChan = emptyHexViewTimer.C
		}

		// This should really be moved to a handler...
		if loader.State() == 0 {
			if loader.State() != prevstate {
				// If the state is now 0, it means no interface-reading process is running. That means
				// we will no longer be reading from an interface or a fifo, so we point the loader at
				// the file we wrote to the cache, and redirect all loads/filters to that now.
				loader.TurnOffPipe()
				if quitRequested {
					app.Quit()
				}
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					clearProgressWidget(app)
					setProgressDeterminate(app) // always switch back - for pdml (partial) loads of later data.
				}))
				// When the progress bar is enabled, track the previous percentage reached. This
				// is so that I don't go "backwards" if I generate a progress value less than the last
				// one, using the current algorithm (because it would be confusing to see it go backwards)
				prev = 0.0
			}
		}

		if loader.State()&(pcap.LoadingPdml|pcap.LoadingPsml) != 0 {
			tickChan = progTicker.C // progress is only enabled when a pcap may be loading
		}

		if loader.State()&pcap.LoadingPdml != 0 {
			pdmlFinChan = loaderPdmlFinChan
		}

		if loader.State()&pcap.LoadingPsml != 0 {
			psmlFinChan = loaderPsmlFinChan
		}

		if loader.State()&pcap.LoadingIface != 0 {
			ifaceFinChan = loaderIfaceFinChan
		}

		// (User) operations are enabled by default (the test predicate is nil), or if the predicate returns true
		// meaning the operation has reached its desired state. Only one operation can be in progress at a time.
		if scheduler.IsEnabled() {
			opsChan = scheduler.OperationsChan
		}

		// This tracks a temporary pcap file which is populated by dumpcap when termshark is
		// reading from a fifo. If iwatcher is nil, it means we've got data and don't need to
		// monitor any more.
		if iwatcher != nil {
			tmpPcapWatcherChan = iwatcher.Events
			tmpPcapWatcherErrorsChan = iwatcher.Errors
		}

		// Only process tcell and gowid events if the UI is running.
		if uiRunning {
			tcellEvents = app.TCellEvents
		}

		afterRenderEvents = app.AfterRenderEvents

		prevstate = loader.State()

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
				openError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
			}

			uiRunning = true
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
				loader.Close()

				appRunner.Stop()
				app.Close()
				uiRunning = false
			}()

		case <-quitRequestedChan:
			if loader.State() == 0 {

				// Only explicitly quit if this flag isn't set because if it is set, then the quit
				// will happen before the select{} statement above
				if !quitRequested {
					app.Quit()
				}

				// If the UI isn't running, then there aren't app events, and that channel is used
				// to break the select loop. So break it manually.
				if !uiRunning {
					break Loop
				}
			} else {
				quitRequested = true
				// We know we're not idle, so stop any load so the quit op happens quickly for the user. Quit
				// will happen next time round because the quitRequested flag is checked.
				scheduler.RequestStopLoad(noHandlers{})
			}

		case sig := <-sigChan:
			if termshark.IsSigTSTP(sig) {
				if uiRunning {
					// Remove our terminal overrides that allow ctrl-z
					ctrlzLineDisc.Restore()
					// Stop tcell/gowid events for keys, etc
					appRunner.Stop()
					// Go back to terminal view
					app.DeactivateScreen()

					uiRunning = false
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
						openError(fmt.Sprintf("Unexpected error setting Ctrl-z handler: %v\n", err), app)
					}

					uiRunning = true
					uiSuspended = false
				}
			} else {
				log.Infof("Starting termination via signal %v", sig)
				quitRequestedChan <- struct{}{}
			}

		case fn := <-opsChan:
			// We run the requested operation - because operations are now enabled, since this channel
			// is listening - and the result tells us when operations can be re-enabled (i.e. the target
			// state of the operation just started, for example). This means we can let an operation
			// "complete", moving through a sequence of states to the final state, befpre accepting
			// another request.
			fn()

		case <-cacheRequestsChan:
			cacheRequests = pcap.ProcessPdmlRequests(cacheRequests, loader,
				struct {
					setNewPdmlRequests
					setStructWidgets
				}{
					setNewPdmlRequests{scheduler},
					setStructWidgets{loader, app},
				})

		case <-ifaceFinChan:
			// this state change only happens if the load from the interface is explicitly
			// stopped by the user (e.g. the stop button). When the current data has come
			// from loading from an interface, when stopped we still want to be able to filter
			// on that data. So the load routines should treat it like a regular pcap
			// (until the interface is started again). That means the psml reader should read
			// from the file and not the fifo.
			loaderIfaceFinChan = loader.IfaceFinishedChan
			loader.SetState(loader.State() & ^pcap.LoadingIface)

		case <-psmlFinChan:
			if loader.LoadWasCancelled {
				// Don't reset cancel state here. If, after stopping an interface load, I
				// apply a filter, I need to know if the load was cancelled previously because
				// if it was cancelled, I need to load from the temp pcap; if not cancelled,
				// (meaning still running), then I just apply a new filter and have the pcap
				// reader read from the fifo. Only do this if the user isn't quitting the app,
				// otherwise it looks clumsy.
				if !quitRequested {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						openError("Loading was cancelled.", app)
					}))
				}
			}
			// Reset
			loaderPsmlFinChan = loader.PsmlFinishedChan
			loader.SetState(loader.State() & ^pcap.LoadingPsml)

		case <-pdmlFinChan:
			loaderPdmlFinChan = loader.Stage2FinishedChan
			loader.SetState(loader.State() & ^pcap.LoadingPdml)

		case <-tickChan:
			if termshark.HaveFdinfo && (loader.State() == pcap.LoadingPdml || !loader.ReadingFromFifo()) {
				prev = updateProgressBarForFile(loader, prev, app)
			} else {
				updateProgressBarForInterface(loader, app)
			}

		case <-emptyStructViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				singlePacketViewMsgHolder.SetSubWidget(loadingw, app)
				packetStructureViewHolder.SetSubWidget(missingMsgw, app)
				emptyStructViewTimer = nil
			}))

		case <-emptyHexViewChan:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				singlePacketViewMsgHolder.SetSubWidget(loadingw, app)
				packetHexViewHolder.SetSubWidget(missingMsgw, app)
				emptyHexViewTimer = nil
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
			configChangedFn(app)
		}

	}

	return 0
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
