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
	isatty "github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// TODO - just for debugging
var ensureGoroutinesStopWG sync.WaitGroup

// Global so that we can change the displayed packet in the struct view, etc
// test
var topview *holder.Widget
var yesno *dialog.Widget
var pleaseWait *dialog.Widget
var pleaseWaitSpinner *spinner.Widget
var mainviewRs *resizable.PileWidget
var mainview gowid.IWidget
var altviewRs *resizable.PileWidget
var altview gowid.IWidget
var altviewpile *resizable.PileWidget
var altviewcols *resizable.ColumnsWidget
var viewOnlyPacketList *pile.Widget
var viewOnlyPacketStructure *pile.Widget
var viewOnlyPacketHex *pile.Widget
var filterCols *columns.Widget
var progWidgetIdx int
var mainViewPaths [][]interface{}
var altViewPaths [][]interface{}
var maxViewPath []interface{}
var filterPathMain []interface{}
var filterPathAlt []interface{}
var filterPathMax []interface{}
var view1idx int
var view2idx int
var menu1 *menu.Widget
var savedMenu *menu.Widget
var filterWidget *filter.Widget
var btnSite *menu.SiteWidget
var packetListViewHolder *holder.Widget
var packetListTable *table.BoundedWidget
var packetStructureViewHolder *holder.Widget
var packetHexViewHolder *holder.Widget
var progressHolder *holder.Widget
var loadProgress *progress.Widget
var loadSpinner *spinner.Widget

var nullw *null.Widget
var loadingw gowid.IWidget
var structmsgHolder *holder.Widget
var missingMsgw gowid.IWidget
var fillSpace *fill.Widget
var fillVBar *fill.Widget
var colSpace *gowid.ContainerWidget

var packetStructWidgets *lru.Cache
var packetHexWidgets *lru.Cache
var packetListView *rowFocusTableWidget

var cacheRequests []pcap.LoadPcapSlice
var cacheRequestsChan chan struct{} // false means started, true means finished
var quitRequestedChan chan struct{}
var loader *pcap.Loader
var scheduler *pcap.Scheduler
var captureFilter string // global for now, might make it possible to change in app at some point
var tmplData map[string]interface{}

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

	//                                                   256 color   < 256 color
	pktListRowSelectedBg  *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	pktListRowFocusBg     *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	pktListCellSelectedBg *modeswap.Color = modeswap.New(darkGray, gowid.ColorBlack)
	pktStructSelectedBg   *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	pktStructFocusBg      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexTopUnselectedFg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	hexTopUnselectedBg    *modeswap.Color = modeswap.New(mediumGray, gowid.ColorBlack)
	hexTopSelectedFg      *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	hexTopSelectedBg      *modeswap.Color = modeswap.New(brightBlue, gowid.ColorBlue)
	hexBottomUnselectedFg *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexBottomUnselectedBg *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	hexBottomSelectedFg   *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexBottomSelectedBg   *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	hexCurUnselectedFg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	hexCurUnselectedBg    *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineFg             *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	hexLineBg             *modeswap.Color = modeswap.New(lightGray, gowid.ColorBlack)
	filterValidBg         *modeswap.Color = modeswap.New(brightGreen, gowid.ColorGreen)

	palette gowid.Palette = gowid.Palette{
		"default":                gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorWhite),
		"title":                  gowid.MakeForeground(gowid.ColorDarkRed),
		"pkt-struct-focus":       gowid.MakePaletteEntry(gowid.ColorWhite, pktStructFocusBg),
		"pkt-struct-selected":    gowid.MakePaletteEntry(gowid.ColorWhite, pktStructSelectedBg),
		"pkt-list-row-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, pktListRowFocusBg),
		"pkt-list-cell-focus":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorPurple),
		"pkt-list-row-selected":  gowid.MakePaletteEntry(gowid.ColorWhite, pktListRowSelectedBg),
		"pkt-list-cell-selected": gowid.MakePaletteEntry(gowid.ColorWhite, pktListCellSelectedBg),
		"filter-menu-focus":      gowid.MakeStyledPaletteEntry(gowid.ColorBlack, gowid.ColorWhite, gowid.StyleBold),
		"filter-valid":           gowid.MakePaletteEntry(gowid.ColorBlack, filterValidBg),
		"filter-invalid":         gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorRed),
		"filter-intermediate":    gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorOrange),
		"dialog":                 gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"dialog-buttons":         gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"stop-load-button":       gowid.MakeForeground(gowid.ColorMagenta),
		"stop-load-button-focus": gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"menu-button":            gowid.MakeForeground(gowid.ColorMagenta),
		"menu-button-focus":      gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"saved-button":           gowid.MakeForeground(gowid.ColorMagenta),
		"saved-button-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"apply-button":           gowid.MakeForeground(gowid.ColorMagenta),
		"apply-button-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"progress-default":       gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"progress-complete":      gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(gowid.ColorMagenta)),
		"progress-spinner":       gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"hex-cur-selected":       gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"hex-cur-unselected":     gowid.MakePaletteEntry(hexCurUnselectedFg, hexCurUnselectedBg),
		"hex-top-selected":       gowid.MakePaletteEntry(hexTopSelectedFg, hexTopSelectedBg),
		"hex-top-unselected":     gowid.MakePaletteEntry(hexTopUnselectedFg, hexTopUnselectedBg),
		"hex-bottom-selected":    gowid.MakePaletteEntry(hexBottomSelectedFg, hexBottomSelectedBg),
		"hex-bottom-unselected":  gowid.MakePaletteEntry(hexBottomUnselectedFg, hexBottomUnselectedBg),
		"hexln-selected":         gowid.MakePaletteEntry(hexLineFg, hexLineBg),
		"hexln-unselected":       gowid.MakePaletteEntry(hexLineFg, hexLineBg),
		"copy-mode-indicator":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkRed),
		"copy-mode":              gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
	}

	helpTmpl = template.Must(template.New("Help").Parse(`
{{define "NameVer"}}termshark v{{.Version}}{{end}}

{{define "OneLine"}}A wireshark-inspired terminal user interface for tshark. Analyze network traffic interactively from your terminal.{{end}}

{{define "Header"}}{{template "NameVer" .}}

{{template "OneLine"}}
See https://github.com/gcla/termshark for more information.{{end}}

{{define "Footer"}}
If --pass-thru is true (or auto, and stdout is not a tty), tshark will be
executed with the supplied command- line flags. You can provide
tshark-specific flags and they will be passed through to tshark (-n, -d, -T,
etc). For example:

$ termshark -r file.pcap -T psml -n | less{{end}}

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
left     - Select next outer-most widget
right    - Select next inner-most widget{{end}}
'?'      - Display copy-mode help
`))

	// Used to determine if we should run tshark instead e.g. stdout is not a tty
	tsopts struct {
		PassThru string `long:"pass-thru" default:"auto" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"auto" choice:"true" choice:"false" description:"Run tshark instead (auto => if stdout is not a tty)."`
	}

	// Termshark's own command line arguments. Used if we don't pass through to tshark.
	opts struct {
		Iface         string         `value-name:"<interface>" short:"i" description:"Interface to read."`
		Pcap          flags.Filename `value-name:"<file>" short:"r" description:"Pcap file to read."`
		DecodeAs      []string       `short:"d" description:"Specify dissection of layer type." value-name:"<layer type>==<selector>,<decode-as protocol>"`
		DisplayFilter string         `short:"Y" description:"Apply display filter." value-name:"<displaY filter>"`
		CaptureFilter string         `short:"f" description:"Apply capture filter." value-name:"<capture filter>"`
		PassThru      string         `long:"pass-thru" default:"auto" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"auto" choice:"true" choice:"false" description:"Run tshark instead (auto => if stdout is not a tty)."`
		LogTty        string         `long:"log-tty" default:"false" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"true" choice:"false" description:"Log to the terminal.."`
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
		"Version": termshark.Version,
	}
	quitRequestedChan = make(chan struct{}, 1) // buffered because send happens from ui goroutine, which runs global select
	cacheRequestsChan = make(chan struct{}, 1000)
	cacheRequests = make([]pcap.LoadPcapSlice, 0)
}

//======================================================================

func writeHelp(p *flags.Parser, w io.Writer) {
	if err := helpTmpl.ExecuteTemplate(w, "Header", tmplData); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
	p.WriteHelp(w)

	if err := helpTmpl.ExecuteTemplate(w, "Footer", tmplData); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

func writeVersion(p *flags.Parser, w io.Writer) {
	if err := helpTmpl.ExecuteTemplate(w, "NameVer", tmplData); err != nil {
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
	packetStructWidgets.Purge()
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

	// We know ou tree widget will never display the root node, so everything will be indented at
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
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)

	dialog.OpenExt(yesno, topview, fixed, fixed, app)
}

func openHelp(tmplName string, app gowid.IApp) {
	yesno = dialog.New(framed.NewSpace(text.New(termshark.TemplateToString(helpTmpl, tmplName, tmplData))),
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
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
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)
	yesno.Open(topview, units(len(msgt)+20), app)
}

//======================================================================

type stateHandler struct {
	sc *pcap.Scheduler
}

func (s stateHandler) EnableOperations() {
	s.sc.Enable()
}

//======================================================================

type updatePacketViews struct {
	ld           *pcap.Scheduler
	app          gowid.IApp
	stateHandler // send idle and iface state changes to global channels
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
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		openError(fmt.Sprintf("%v", err), app)
	}))
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
							menu1HotKeys[i],
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
		mainviewRs.AdjustOffset(2, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRs.AdjustOffset(2, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func appKeysResize2(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		mainviewRs.AdjustOffset(4, 6, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		mainviewRs.AdjustOffset(4, 6, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func viewcolsaKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '>' {
		altviewcols.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '<' {
		altviewcols.AdjustOffset(0, 2, resizable.Subtract1, app)
	} else {
		handled = false
	}
	return handled
}

func viewpilebKeyPress(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := true
	if evk.Rune() == '+' {
		altviewpile.AdjustOffset(0, 2, resizable.Add1, app)
	} else if evk.Rune() == '-' {
		altviewpile.AdjustOffset(0, 2, resizable.Subtract1, app)
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
			scheduler.RequestStopLoad(stateHandler{}) // iface and psml
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
			gowid.SetFocusPath(mainview, mainViewPaths[0], app)
			gowid.SetFocusPath(altview, altViewPaths[0], app)
		} else {
			newidx := -1
			if topview.SubWidget() == mainview {
				v1p := gowid.FocusPath(mainview)
				if deep.Equal(v1p, mainViewPaths[0]) == nil {
					newidx = 1
				} else if deep.Equal(v1p, mainViewPaths[1]) == nil {
					newidx = 2
				} else {
					newidx = 0
				}
			} else if topview.SubWidget() == altview {
				v2p := gowid.FocusPath(altview)
				if deep.Equal(v2p, altViewPaths[0]) == nil {
					newidx = 1
				} else if deep.Equal(v2p, altViewPaths[1]) == nil {
					newidx = 2
				} else {
					newidx = 0
				}
			}

			if newidx != -1 {
				// Keep the views in sync
				gowid.SetFocusPath(mainview, mainViewPaths[newidx], app)
				gowid.SetFocusPath(altview, altViewPaths[newidx], app)
			}
		}

	} else if evk.Key() == tcell.KeyEscape {
		menu1.Open(btnSite, app)
	} else if evk.Rune() == '|' {
		if topview.SubWidget() == mainview {
			topview.SetSubWidget(altview, app)
		} else {
			topview.SetSubWidget(mainview, app)
		}
	} else if evk.Rune() == '\\' {
		w := topview.SubWidget()
		fp := gowid.FocusPath(w)
		if w == viewOnlyPacketList || w == viewOnlyPacketStructure || w == viewOnlyPacketHex {
			topview.SetSubWidget(mainview, app)
			if deep.Equal(fp, maxViewPath) == nil {
				switch w {
				case viewOnlyPacketList:
					gowid.SetFocusPath(mainview, mainViewPaths[0], app)
				case viewOnlyPacketStructure:
					gowid.SetFocusPath(mainview, mainViewPaths[1], app)
				case viewOnlyPacketHex:
					gowid.SetFocusPath(mainview, mainViewPaths[2], app)
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
		gowid.SetFocusPath(altview, filterPathAlt, app)
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
	stop2 := styled.NewExt(stop, gowid.MakePaletteRef("stop-load-button"), gowid.MakePaletteRef("stop-load-button-focus"))

	stop.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		scheduler.RequestStopLoad(stateHandler{})
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

func setLowerWidgets(app gowid.IApp) {
	var sw1 gowid.IWidget = missingMsgw
	var sw2 gowid.IWidget = missingMsgw
	if packetListView != nil {
		if fxy, err := packetListView.FocusXY(); err == nil {
			row2 := fxy.Row
			row3, _ := packetListView.Model().RowIdentifier(row2)
			row := int(row3)

			hex := getHexWidgetToDisplay(row)
			if hex == nil {
				sw1 = missingMsgw
			} else {
				// The 't' key will switch from hex <-> ascii
				sw1 = enableselected.New(appkeys.New(
					hex,
					hex.OnKey(func(ev *tcell.EventKey) bool {
						return ev.Rune() == 't'
					}).SwitchView,
				))
			}
			//str := getStructWidgetToDisplay(row, hex)
			str := getStructWidgetToDisplay(row, app)
			if str == nil {
				sw2 = missingMsgw
			} else {
				sw2 = enableselected.New(str)
			}
		}
	}
	packetHexViewHolder.SetSubWidget(sw1, app)
	packetStructureViewHolder.SetSubWidget(sw2, app)
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
	packetListTable.SetModel(model, app)
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
	if val, ok := packetStructWidgets.Get(row); ok {
		trw := val.(*copymodetree.Widget)

		walker := trw.Walker().(*termshark.NoRootWalker)
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
				chosenTree.Expanded = true
				finalPos = append(finalPos, chosenIdx+hack)
				curTree = chosenTree
				hack = 0
			} else {
				// didn't find any
				break Out
			}
		}
		if len(finalPos) > 0 {
			tp := tree.NewPosExt(finalPos)
			// this is to account for the fact that noRootWalker returns the next widget
			// in the tree. Whatever position we find, we need to go back one to make up for this.
			walker.SetFocus(tp, app)
			trw.GoToMiddle(app)
		}
	}
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

			tr := pdmltree.DecodePacket(data)
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
				res2 = hexdumper.New(b, layers,
					"hex-cur-unselected", "hex-cur-selected",
					"hexln-unselected", "hexln-selected",
					"copy-mode",
				)

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
						if deep.Equal(v1p, mainViewPaths[2]) != nil { // it's not hex
							return
						}
					} else {
						v2p := gowid.FocusPath(altview)
						if deep.Equal(v2p, altViewPaths[2]) != nil { // it's not hex
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
func getStructWidgetToDisplay(row int, app gowid.IApp) gowid.IWidget {
	var res gowid.IWidget = missingMsgw

	if val, ok := packetStructWidgets.Get(row); ok {
		res = val.(gowid.IWidget)
	} else {
		row2 := (row / 1000) * 1000
		if ws, ok := loader.PacketCache.Get(row2); ok {
			srca := ws.(pcap.CacheEntry).Pdml
			if len(srca) > row%1000 {
				data, err := xml.Marshal(srca[row%1000])
				if err != nil {
					log.Fatal(err)
				}

				tr := pdmltree.DecodePacket(data)
				tr.Expanded = true

				var pos tree.IPos = tree.NewPos()
				pos = tree.NextPosition(pos, tr) // Start ahead by one, then never go back

				// Without the caching layer, clicking on a button has no effect
				walker := termshark.NewNoRootWalker(tree.NewWalker(tr, pos,
					tree.NewCachingMaker(tree.WidgetMakerFunction(makeStructNodeWidget)),
					tree.NewCachingDecorator(tree.DecoratorFunction(makeStructNodeDecoration))))

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

				walker.OnFocusChanged(tree.MakeCallback("cb", func(app gowid.IApp, twalker tree.ITreeWalker) {
					updateHex(app, twalker)
				}))

				updateHex(app, walker)

				tb := copymodetree.New(tree.New(walker), copyModePalette{})
				res = tb
				packetStructWidgets.Add(row, res)
			}
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
		addToRecentFiles(t.pcap)
	}
	if t.filter != "" {
		addToRecentFilters(t.filter)
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

type configError struct {
	Name string
	Msg  string
}

var _ error = configError{}

func (e configError) Error() string {
	return fmt.Sprintf("Config error for key %s: %s", e.Name, e.Msg)
}

//======================================================================

func loadOffsetFromConfig(name string) ([]resizable.Offset, error) {
	offsStr := viper.GetString("main." + name)
	if offsStr == "" {
		return nil, errors.WithStack(configError{Name: name, Msg: "No offsets found"})
	}
	res := make([]resizable.Offset, 0)
	err := json.Unmarshal([]byte(offsStr), &res)
	if err != nil {
		return nil, errors.WithStack(configError{Name: name, Msg: "Could not unmarshal offsets"})
	}
	return res, nil
}

func saveOffsetToConfig(name string, offsets2 []resizable.Offset) {
	offsets := make([]resizable.Offset, 0)
	for _, off := range offsets2 {
		if off.Adjust != 0 {
			offsets = append(offsets, off)
		}
	}
	if len(offsets) == 0 {
		delete(viper.Get("main").(map[string]interface{}), name)
	} else {
		offs, err := json.Marshal(offsets)
		if err != nil {
			log.Fatal(err)
		}
		viper.Set("main."+name, string(offs))
	}
	// Hack to make viper save if I only deleted from the map
	viper.Set("main.lastupdate", time.Now().String())
	viper.WriteConfig()
}

func addToRecentFiles(pcap string) {
	comps := viper.GetStringSlice("main.recent-files")
	if len(comps) == 0 || comps[0] != pcap {
		comps = termshark.RemoveFromStringSlice(pcap, comps)
		if len(comps) > 16 {
			comps = comps[0 : 16-1]
		}
		viper.Set("main.recent-files", comps)
		viper.WriteConfig()
	}
}

func addToRecentFilters(val string) {
	comps := viper.GetStringSlice("main.recent-filters")
	if (len(comps) == 0 || comps[0] != val) && strings.TrimSpace(val) != "" {
		comps = termshark.RemoveFromStringSlice(val, comps)
		if len(comps) > 64 {
			comps = comps[0 : 64-1]
		}
		viper.Set("main.recent-filters", comps)
		viper.WriteConfig()
	}
}

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
		comps := viper.GetStringSlice("main.recent-filters")
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

	s.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		structmsgHolder.SetSubWidget(loadingw, s.app)
	}))

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
		structmsgHolder.SetSubWidget(nullw, app)
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
	if passthru && (flagIsTrue(tsopts.PassThru) || (tsopts.PassThru == "auto" && !isatty.IsTerminal(os.Stdout.Fd()))) {
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
		fmt.Printf("Command-line error: %v\n\n", err)
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

	pcapf := string(opts.Pcap)

	// If no interface specified, and no pcap specified via -r, then we assume the first
	// argument is a pcap file e.g. termshark foo.pcap
	if pcapf == "" && opts.Iface == "" {
		pcapf = string(opts.Args.FilterOrFile)
	} else {
		// Add it to filter args. Figure out later if they're capture or display.
		filterArgs = append(filterArgs, opts.Args.FilterOrFile)
	}

	if pcapf != "" && opts.Iface != "" {
		fmt.Fprintf(os.Stderr, "Please supply either a pcap or an interface.\n")
		return 1
	}

	// go-flags returns [""] when no extra args are provided, so I can't just
	// test the length of this slice
	argsFilter := strings.Join(filterArgs, " ")

	// Work out capture filter afterwards because we need to determine first
	// whether any potential first argument is intended as a pcap file instead of
	// a capture filter.
	captureFilter = opts.CaptureFilter

	if opts.Iface != "" && argsFilter != "" {
		if opts.CaptureFilter != "" {
			fmt.Fprintf(os.Stderr, "Two capture filters provided - '%s' and '%s' - please supply one only.\n", opts.CaptureFilter, argsFilter)
			return 1
		}
		captureFilter = argsFilter
	}

	displayFilter := opts.DisplayFilter

	if pcapf != "" {
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

	// Better to do a command-line error if file supplied at command-line is not found.
	if pcapf != "" {
		if _, err := os.Stat(pcapf); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v.\n", pcapf, err)
			return 1
		}
	}

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
	if viper.Get("tshark") != nil {
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

	valids := viper.GetStringSlice("main.validated-tsharks")

	if !termshark.StringInSlice(tsharkBin, valids) {
		tver, err := termshark.TSharkVersion(tsharkBin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not determine tshark version: %v\n", err)
			return 1
		}
		// This is the earliest version I could determine gives reliable results in termshark.
		// tshark compiled against tag v1.10.1 doesn't populate the hex view.
		mver, _ := semver.Make("1.10.2")
		if tver.LTE(mver) {
			fmt.Fprintf(os.Stderr, "termshark will not operate correctly with a tshark older than %v (found %v)\n", mver, tver)
			return 1
		}

		valids = append(valids, tsharkBin)
		viper.Set("main.validated-tsharks", valids)
		viper.WriteConfig()
	}

	cacheDir := termshark.CacheDir()
	if _, err = os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.Mkdir(cacheDir, 0777)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unexpected error making cache dir %s: %v", cacheDir, err)
			return 1
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
	useIface := opts.Iface

	if opts.Iface != "" {
		//ifaces, err := net.Interfaces()
		ifaces, err := termshark.Interfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not enumerate network interfaces: %v\n", err)
			return 1
		}
		gotit := false

		// Check if opts.Iface was provided as a number
		ifaceIdx, err := strconv.Atoi(opts.Iface)
		if err != nil {
			ifaceIdx = -1
		}

		for n, i := range ifaces {
			if i == opts.Iface || n+1 == ifaceIdx {
				gotit = true
				useIface = i
				break
			}
		}
		if !gotit {
			fmt.Fprintf(os.Stderr, "Could not find network interface %s\n", opts.Iface)
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

	startedWithIface := false

	defer func() {
		if startedWithIface && loader != nil {
			fmt.Printf("Packets read from interface %s have been saved in %s\n", loader.Interface(), loader.InterfaceFile())
		}
	}()

	//======================================================================

	ifaceExitCode := 0
	var ifaceErr error

	// This is deferred until after the app is Closed - otherwise messages written to stdout/stderr are
	// swallowed by tcell.
	defer func() {
		if ifaceExitCode != 0 {
			fmt.Printf("Cannot capture on interface %s", useIface)
			if ifaceErr != nil {
				fmt.Printf(": %v", ifaceErr)
			}
			fmt.Printf(" (exit code %d)\n", ifaceExitCode)
			fmt.Printf("See https://wiki.wireshark.org/CaptureSetup/CapturePrivileges for more info.\n")
		}
	}()

	//======================================================================
	//
	// Build the UI

	var app *gowid.App

	widgetCacheSize := termshark.ConfInt("main.ui-cache-size", 1000)
	if widgetCacheSize < 64 {
		widgetCacheSize = 64
	}
	packetStructWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		fmt.Printf("Internal error: %v\n", err)
		return 1
	}
	packetHexWidgets, err = lru.New(widgetCacheSize)
	if err != nil {
		fmt.Printf("Internal error: %v\n", err)
		return 1
	}

	nullw = null.New()

	loadingw = text.New("Loading, please wait...")
	structmsgHolder = holder.New(loadingw)
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
		hpadding.New(structmsgHolder, hmiddle, fixed),
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
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)

	openMenu := button.New(text.New("Menu"))
	openMenu2 := styled.NewExt(openMenu, gowid.MakePaletteRef("menu-button"), gowid.MakePaletteRef("menu-button-focus"))

	btnSite = menu.NewSite(menu.SiteOptions{YOffset: 1})
	openMenu.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		menu1.Open(btnSite, app)
	}))

	title := styled.New(text.New(termshark.TemplateToString(helpTmpl, "NameVer", tmplData)), gowid.MakePaletteRef("title"))

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

	menu1items := []simpleMenuItem{
		simpleMenuItem{
			Txt: "Help",
			Key: gowid.MakeKey('?'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				menu1.Close(app)
				openHelp("UIHelp", app)
			},
		},
		simpleMenuItem{
			Txt: "Clear Packets",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlW, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				menu1.Close(app)
				reallyClear(app)
			},
		},
		simpleMenuItem{
			Txt: "Refresh Screen",
			Key: gowid.MakeKeyExt2(0, tcell.KeyCtrlL, ' '),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				menu1.Close(app)
				app.Sync()
			},
		},
		simpleMenuItem{
			Txt: "Quit",
			Key: gowid.MakeKey('q'),
			CB: func(app gowid.IApp, w gowid.IWidget) {
				menu1.Close(app)
				reallyQuit(app)
			},
		},
	}

	menuListBox1 := makeRecentMenu(menu1items)
	menu1 = menu.New("main", menuListBox1, fixed, menu.Options{
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
			IWidget: btnSite,
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
	applyWidget2 := styled.NewExt(applyw, gowid.MakePaletteRef("apply-button"), gowid.MakePaletteRef("apply-button-focus"))
	applyWidget := disable.NewEnabled(applyWidget2)

	filterWidget = filter.New(filter.Options{
		Completer: savedCompleter{def: termshark.NewFields()},
	})

	defer filterWidget.Close()

	applyw.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		scheduler.RequestNewFilter(filterWidget.Value(), makePacketViewUpdater(app))
	}))

	filterWidget.OnValid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Enable()
	}))
	filterWidget.OnInvalid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		applyWidget.Disable()
	}))
	filterLabel := text.New("Filter: ")

	savedw := button.New(text.New("Recent"))
	savedWidget := styled.NewExt(savedw, gowid.MakePaletteRef("saved-button"), gowid.MakePaletteRef("saved-button-focus"))
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

	mainviewRs = resizable.NewPile([]gowid.IContainerWidget{
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

	mainviewRs.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		saveOffsetToConfig("mainview", mainviewRs.GetOffsets())
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

	altviewpile = resizable.NewPile([]gowid.IContainerWidget{
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

	altviewpile.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		saveOffsetToConfig("altviewleft", altviewpile.GetOffsets())
	}))

	viewpilebkeys := appkeys.New(altviewpile, viewpilebKeyPress)

	altviewcols = resizable.NewColumns([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: viewpilebkeys,
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

	altviewcols.OnOffsetsSet(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		saveOffsetToConfig("altviewright", altviewcols.GetOffsets())
	}))

	viewcolsakeys := appkeys.New(altviewcols, viewcolsaKeyPress)

	altviewRs = resizable.NewPile([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: titleView,
			D:       units(1),
		},
		&gowid.ContainerWidget{
			IWidget: filterView,
			D:       units(3),
		},
		&gowid.ContainerWidget{
			IWidget: viewcolsakeys,
			D:       weight(1),
		},
	})

	maxViewPath = []interface{}{2, 0} // list, structure or hex - whichever one is selected

	mainViewPaths = [][]interface{}{
		{2, 0}, // packet list
		{4},    // packet structure
		{6},    // packet hex
	}

	altViewPaths = [][]interface{}{
		{2, 0, 0, 0}, // packet list
		{2, 0, 2},    // packet structure
		{2, 2},       // packet hex
	}

	filterPathMain = []interface{}{1, 1}
	filterPathAlt = []interface{}{1, 1}
	filterPathMax = []interface{}{1, 1}

	mainview = mainviewRs
	altview = altviewRs

	topview = holder.New(mainview)

	keylayer := appkeys.New(topview, appKeyPress)

	app, err = gowid.NewApp(gowid.AppArgs{
		View:    keylayer,
		Palette: &palette,
		Log:     log.StandardLogger(),
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return 1
	}
	defer app.Close()

	for _, m := range filterWidget.Menus() {
		app.RegisterMenu(m)
	}
	app.RegisterMenu(savedMenu)
	app.RegisterMenu(menu1)

	// Populate the filter widget initially - runs asynchronously
	go filterWidget.UpdateCompletions(app)

	gowid.SetFocusPath(mainview, mainViewPaths[0], app)
	gowid.SetFocusPath(altview, altViewPaths[0], app)

	if offs, err := loadOffsetFromConfig("mainview"); err == nil {
		mainviewRs.SetOffsets(offs, app)
	}
	if offs, err := loadOffsetFromConfig("altviewleft"); err == nil {
		altviewpile.SetOffsets(offs, app)
	}
	if offs, err := loadOffsetFromConfig("altviewright"); err == nil {
		altviewcols.SetOffsets(offs, app)
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

	validator := filter.Validator{
		Invalid: &filter.ValidateCB{
			App: app,
			Fn: func(app gowid.IApp) {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					openError(fmt.Sprintf("Invalid filter: %s", displayFilter), app)
				}))
			},
		},
	}

	if pcapf != "" {
		if pcapf, err = filepath.Abs(pcapf); err != nil {
			fmt.Printf("Could not determine working directory: %v\n", err)
			return 1
		} else {
			doit := func(app gowid.IApp) {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					filterWidget.SetValue(displayFilter, app)
				}))
				requestLoadPcapWithCheck(pcapf, displayFilter, app)
			}
			validator.Valid = &filter.ValidateCB{Fn: doit, App: app}
			validator.Validate(displayFilter)
		}
	} else if useIface != "" {

		// Verifies whether or not we will be able to read from the interface (hopefully)
		ifaceExitCode = -1
		if ifaceExitCode, ifaceErr = termshark.RunForExitCode("dumpcap", "-i", useIface, "-a", "duration:1", "-w", os.DevNull); ifaceExitCode != 0 {
			return 1
		}

		doit := func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				filterWidget.SetValue(displayFilter, app)
			}))
			scheduler.RequestLoadInterface(useIface, captureFilter, displayFilter, saveRecents{makePacketViewUpdater(app), "", displayFilter})
			startedWithIface = true
		}
		validator.Valid = &filter.ValidateCB{Fn: doit, App: app}
		validator.Validate(displayFilter)
	}

	// Do this to make sure the program quits quickly if quit is invoked
	// mid-load. It's safe to call this if a pcap isn't being loaded.
	//
	// The regular stopLoadPcap will send a signal to pcapChan. But if qpp.quit
	// is called, the main select{} loop will be broken, and nothing will listen
	// to that channel. As a result, nothing stops a pcap load. This calls the
	// context cancellation function right away
	defer func() {
		loader.Close()
	}()

	st := app.Runner()
	st.Start()
	defer st.Stop()

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

Loop:
	for {
		var opsChan <-chan pcap.RunFn
		var tickChan <-chan time.Time
		var psmlFinChan <-chan struct{}
		var ifaceFinChan <-chan struct{}
		var pdmlFinChan <-chan struct{}

		if loader.State() == 0 {
			if loader.State() != prevstate {
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

		prevstate = loader.State()

		select {
		case <-quitRequestedChan:
			if loader.State() == 0 {
				app.Quit()
			} else {
				quitRequested = true
				// We know we're not idle, so stop any load so the quit op happens quickly for the user.
				scheduler.RequestStopLoad(stateHandler{})
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
				// reader read from the fifo
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					openError("Loading was cancelled.", app)
				}))
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

		case ev := <-app.TCellEvents:
			app.HandleTCellEvent(ev, gowid.IgnoreUnhandledInput)

		case ev, ok := <-app.AfterRenderEvents:
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
