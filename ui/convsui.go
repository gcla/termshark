// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"bufio"
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/convs"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/pkg/psmlmodel"
	"github.com/gcla/termshark/v2/ui/tableutil"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/copymodetable"
	"github.com/gcla/termshark/v2/widgets/enableselected"
	"github.com/gcla/termshark/v2/widgets/keepselected"
	"github.com/gcla/termshark/v2/widgets/scrollabletable"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	"github.com/gdamore/tcell/v2"
)

var convsView *holder.Widget
var convsUi *ConvsUiWidget
var convCancel context.CancelFunc

var convsPcapSize int64 // track size of source, if changes then recalculation conversations

var vdiv string
var frameRunes framed.FrameRunes

type Direction int

const (
	Any  Direction = 0
	To   Direction = iota
	From Direction = iota
)

type ConvAddr int

const (
	IPv4Addr ConvAddr = 0
	IPv6Addr ConvAddr = iota
	MacAddr  ConvAddr = iota
)

type FilterMask int

const (
	AtfB   FilterMask = 0
	AtB    FilterMask = iota
	BtA    FilterMask = iota
	AtfAny FilterMask = iota
	AtAny  FilterMask = iota
	AnytA  FilterMask = iota
	AnytfB FilterMask = iota
	AnytB  FilterMask = iota
	BtAny  FilterMask = iota
)

type FilterCombinator int

const (
	Selected       FilterCombinator = 0
	NotSelected    FilterCombinator = iota
	AndSelected    FilterCombinator = iota
	OrSelected     FilterCombinator = iota
	AndNotSelected FilterCombinator = iota
	OrNotSelected  FilterCombinator = iota
)

// Use to construct a string like "ip.addr == 1.2.3.4 && tcp.port == 12345"
type IFilterBuilder interface {
	fmt.Stringer
	FilterFrom(vals ...string) string
	FilterTo(vals ...string) string
	FilterAny(vals ...string) string
	AIndex() []int
	BIndex() []int
}

var convTypes = map[string]IFilterBuilder{}

func init() {
	convTypes[convs.Ethernet{}.Short()] = convs.Ethernet{}
	convTypes[convs.IPv4{}.Short()] = convs.IPv4{}
	convTypes[convs.IPv6{}.Short()] = convs.IPv6{}
	convTypes[convs.UDP{}.Short()] = convs.UDP{}
	convTypes[convs.TCP{}.Short()] = convs.TCP{}

	if runtime.GOOS == "windows" {
		vdiv = "│"
		frameRunes = framed.FrameRunes{'┌', '┐', '└', '┘', 0, '─', '│', '│'}
	} else {
		vdiv = "┃"
		frameRunes = framed.FrameRunes{'┏', '┓', '┗', '┛', 0, '━', '┃', '┃'}
	}
}

//======================================================================

type ManageConvsCache struct{}

var _ pcap.INewSource = ManageConvsCache{}

// Make sure that existing data is discarded if the user loads a new pcap.
func (t ManageConvsCache) OnNewSource(pcap.HandlerCode, gowid.IApp) {
	convsView = nil // which then deletes all refs to loaded data
	convsPcapSize = 0
}

//======================================================================

type ConvsModel struct {
	*psmlmodel.Model
	proto IFilterBuilder
}

func (m ConvsModel) GetAFilter(row int, dir Direction) string {
	line := m.Data[row]
	parms := []string{}
	for _, idx := range m.proto.AIndex() {
		parms = append(parms, line[idx])
	}
	switch dir {
	case To:
		return m.proto.FilterTo(parms...)
	case From:
		return m.proto.FilterFrom(parms...)
	default:
		return m.proto.FilterAny(parms...)
	}
}

func (m ConvsModel) GetBFilter(row int, dir Direction) string {
	line := m.Data[row]
	parms := []string{}
	for _, idx := range m.proto.BIndex() {
		parms = append(parms, line[idx])
	}
	switch dir {
	case To:
		return m.proto.FilterTo(parms...)
	case From:
		return m.proto.FilterFrom(parms...)
	default:
		return m.proto.FilterAny(parms...)
	}
}

//======================================================================

func convsKeyPress(sections *pile.Widget, evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	switch {
	case evk.Rune() == 'q' || evk.Rune() == 'Q' || evk.Key() == tcell.KeyEscape:
		closeConvsUi(app)
		convCancel()
		handled = true
	case evk.Key() == tcell.KeyTAB:
		if next, ok := sections.FindNextSelectable(gowid.Forwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	case evk.Key() == tcell.KeyBacktab:
		if next, ok := sections.FindNextSelectable(gowid.Backwards, true); ok {
			sections.SetFocus(app, next)
			handled = true
		}
	}
	return handled
}

//======================================================================

type pleaseWait struct{}

func (p pleaseWait) OpenPleaseWait(app gowid.IApp) {
	OpenPleaseWait(appView, app)
}

func (p pleaseWait) ClosePleaseWait(app gowid.IApp) {
	ClosePleaseWait(app)
}

// Dynamically load conv. If the convs window was last opened with a different filter, and the "limit to
// filter" checkbox is checked, then the data needs to be reloaded.
func openConvsUi(app gowid.IApp) {

	var convCtx context.Context
	convCtx, convCancel = context.WithCancel(Loader.Context())

	newSize, reset := termshark.FileSizeDifferentTo(Loader.PcapPdml, convsPcapSize)
	if reset {
		convsView = nil
	}

	// This is nil if a new pcap is loaded (or the old one cleared)
	if convsView == nil {
		convsPcapSize = newSize

		// gcla later todo - PcapPdml - hack?
		convsUi = NewConvsUi(
			Loader.String(),
			Loader.DisplayFilter(),
			Loader.PcapPdml,
			pleaseWait{},
			ConvsUiOptions{
				CopyModeWidget: CopyModeWidget,
			},
		)

		convsView = holder.New(convsUi)
	} else if convsUi.FilterValue() != Loader.DisplayFilter() && convsUi.UseFilter() {
		convsUi.ReloadNeeded()
	}

	convsUi.ctx = convCtx
	convsUi.focusOnFilter = false
	convsUi.displayFilter = Loader.DisplayFilter()

	copyModeConvsView := appkeys.New(
		appkeys.New(
			convsView,
			copyModeExitKeys20,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		copyModeEnterKeys,
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	appViewNoKeys.SetSubWidget(copyModeConvsView, app)
}

func closeConvsUi(app gowid.IApp) {
	appViewNoKeys.SetSubWidget(mainView, app)

	if convsUi.focusOnFilter {
		setFocusOnDisplayFilter(app)
	} else {
		// Do this if the user starts conversations from the menu - better UX
		setFocusOnPacketList(app)
	}
}

//======================================================================

func NewConvsUi(captureDevice string, displayFilter string, pcapf string, pw IPleaseWait, opts ...ConvsUiOptions) *ConvsUiWidget {
	var opt ConvsUiOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &ConvsUiWidget{
		opt:           opt,
		displayFilter: displayFilter,
		captureDevice: captureDevice,
		pcapf:         pcapf,
		pleaseWait:    pw,
		tabIndex:      make(map[string]int),
		buttonLabels:  make(map[string]*text.Widget),
	}

	res.construct()

	return res
}

type IPleaseWait interface {
	OpenPleaseWait(app gowid.IApp)
	ClosePleaseWait(app gowid.IApp)
}

type ConvsUiOptions struct {
	CopyModeWidget gowid.IWidget // What to display when copy-mode is started.
}

type ConvsUiWidget struct {
	gowid.IWidget
	opt                 ConvsUiOptions
	captureDevice       string // "eth0"
	displayFilter       string // "tcp.stream eq 1"
	pcapf               string // "eth0-ddddd.pcap"
	ctx                 context.Context
	pleaseWait          IPleaseWait
	convHolder          *holder.Widget
	convs               []*oneConvWidget        // the widgets displayed in each tab
	prepFiltBtn         *button.Widget          // "Prepare filter" -> click to prep filter
	applyFiltBtn        *button.Widget          // "Apply filter" -> click to prep filter
	filterPrep          bool                    // if true prepare filter, don't apply; otherwise apply immediately
	filterSelectedIndex FilterCombinator        // which filter combination is active e.g. A -> B
	focusOnFilter       bool                    // Whether to set focus on display filter on closing widget
	buttonLabels        map[string]*text.Widget // map "eth" to button, so I can update with a count of conversations
	shortNames          []string                // ["eth", "ip", ...] - from config file
	tabIndex            map[string]int          // {"eth": 0, "ipv6": 2, ...} -> mapping to tabs in UI
	started             bool                    // false if stream load needs to be done, true if under way or done
}

func (w *ConvsUiWidget) AbsoluteTime() bool {
	return profiles.ConfBool("main.conv-absolute-time", false)
}

func (w *ConvsUiWidget) SetAbsoluteTime(val bool) {
	profiles.SetConf("main.conv-absolute-time", val)
}

func (w *ConvsUiWidget) ResolveNames() bool {
	return profiles.ConfBool("main.conv-resolve-names", false)
}

func (w *ConvsUiWidget) SetResolveNames(val bool) {
	profiles.SetConf("main.conv-resolve-names", val)
}

func (w *ConvsUiWidget) Context() context.Context {
	return w.ctx
}

func (w *ConvsUiWidget) FilterValue() string {
	return w.displayFilter
}

func (w *ConvsUiWidget) UseFilter() bool {
	return profiles.ConfBool("main.conv-use-filter", false)
}

func (w *ConvsUiWidget) SetUseFilter(val bool) {
	profiles.SetConf("main.conv-use-filter", val)
}

func (w *ConvsUiWidget) construct() {
	convs := make([]*oneConvWidget, 0)

	header := w.makeHeaderConvsUiWidget()

	convsHeader := columns.NewWithDim(
		gowid.RenderWithWeight{1},
		header,
	)

	colws := make([]interface{}, 0)
	colws = append(colws,
		text.New(vdiv),
	)
	w.shortNames = termshark.ConvTypes()
	// Just in case there are none
	w.convHolder = holder.New(null.New())
	for i, p := range w.shortNames {
		p := p
		i := i

		w.tabIndex[p] = i
		newconv := newOneConv(p)
		convs = append(convs, newconv)

		if i == 0 {
			w.convHolder = holder.New(newconv)
		}

		w.buttonLabels[p] = text.New(fmt.Sprintf(" %s ", convTypes[p]))
		b := button.NewBare(w.buttonLabels[p])
		b.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
			w.convHolder.SetSubWidget(newconv, app)
		}))

		bs := isselected.NewExt(
			b,
			styled.New(b, gowid.MakePaletteRef("button-selected")),
			styled.New(b, gowid.MakePaletteRef("button-focus")),
		)

		colws = append(colws, bs, text.New(vdiv))
	}

	panel := framed.New(w.convHolder, framed.Options{
		Frame: frameRunes,
	})

	cols := keepselected.New(columns.NewFixed(colws...))

	nameCheck := checkbox.New(w.ResolveNames())

	nameCheck.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetResolveNames(nameCheck.IsChecked())
		w.ReloadNeeded()
	}})

	nameLabel := text.New(" Name res.")
	nameW := hpadding.New(
		columns.NewFixed(nameCheck, nameLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	filterCheck := checkbox.New(w.UseFilter())

	filterCheck.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetUseFilter(filterCheck.IsChecked())
		w.ReloadNeeded()
	}})

	filterLabel := text.New(" Limit to filter")
	filterW := hpadding.New(
		columns.NewFixed(filterCheck, filterLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	absTimeCheck := checkbox.New(w.AbsoluteTime())

	absTimeCheck.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.SetAbsoluteTime(absTimeCheck.IsChecked())
		w.ReloadNeeded()
	}})

	absTimeLabel := text.New(" Abs. time")
	absTimeW := hpadding.New(
		columns.NewFixed(absTimeCheck, absTimeLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	prepFiltBtnSite := menu.NewSite(menu.SiteOptions{YOffset: -8})
	w.prepFiltBtn = button.New(text.New("Prep Filter"))
	w.prepFiltBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.filterPrep = true
		filterConvsMenu1.Open(prepFiltBtnSite, app)
	}))

	styledPrepFiltBtn := styled.NewExt(
		w.prepFiltBtn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	prepFiltCols := columns.NewFixed(prepFiltBtnSite, styledPrepFiltBtn)
	prepFiltColsW := hpadding.New(
		prepFiltCols,
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	applyFiltBtnSite := menu.NewSite(menu.SiteOptions{YOffset: -8})
	w.applyFiltBtn = button.New(text.New("Apply Filter"))
	w.applyFiltBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.filterPrep = false
		filterConvsMenu1.Open(applyFiltBtnSite, app)
	}))

	styledApplyFiltBtn := styled.NewExt(
		w.applyFiltBtn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	applyFiltCols := columns.NewFixed(applyFiltBtnSite, styledApplyFiltBtn)
	applyFiltColsW := hpadding.New(
		applyFiltCols,
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	//====================

	bcols := columns.NewWithDim(gowid.RenderWithWeight{W: 1},
		prepFiltColsW,
		applyFiltColsW,
		nameW,
		filterW,
		absTimeW,
	)

	main := pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: convsHeader,
			D:       gowid.RenderWithUnits{U: 2},
		},
		&gowid.ContainerWidget{
			IWidget: cols,
			D:       gowid.RenderWithUnits{U: 1},
		},
		&gowid.ContainerWidget{
			IWidget: panel,
			D:       gowid.RenderWithWeight{W: 1},
		},
		&gowid.ContainerWidget{
			IWidget: bcols,
			D:       gowid.RenderWithUnits{U: 1},
		},
	})

	w.IWidget = appkeys.New(
		main,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			return convsKeyPress(main, ev, app)
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)
	w.convs = convs
}

func (w *ConvsUiWidget) ReloadNeeded() {
	w.started = false
}

func (w *ConvsUiWidget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if !w.started {
		w.started = true

		ld := convs.NewLoader(convs.MakeCommands(), w.Context())

		handler := convsParseHandler{
			app:    app,
			ondata: w,
		}

		filter := ""
		if w.UseFilter() {
			filter = w.FilterValue()
		}

		ld.StartLoad(
			w.pcapf,
			w.shortNames,
			//w.ctype,
			filter,
			w.AbsoluteTime(),
			w.ResolveNames(),
			app,
			&handler,
		)

	}
	return w.IWidget.Render(size, focus, app)
}

// The widget displayed in the first line of the stream reassembly UI.
func (w *ConvsUiWidget) makeHeaderConvsUiWidget() gowid.IWidget {
	var headerText string
	var headerText1 string
	var headerText2 string
	var headerText3 string
	headerText1 = "Conversations"
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

// convsModelWithRow is able to provide an A and a B for a conversation A <-> B. It looks
// up the model at a specific row to find the conversation.
type convsModelWithRow struct {
	model *ConvsModel
	row   int
}

var _ IFilterModel = (*convsModelWithRow)(nil)

func (c *convsModelWithRow) GetAFilter(dir Direction) string {
	return c.model.GetAFilter(c.row, dir)
}

func (c *convsModelWithRow) GetBFilter(dir Direction) string {
	return c.model.GetBFilter(c.row, dir)
}

func (w *ConvsUiWidget) doFilterMenuOp(dirOp FilterMask, app gowid.IApp) {
	conv1 := w.convHolder.SubWidget()
	if conv1 != nil {
		if conv1, ok := conv1.(*oneConvWidget); ok {
			if conv1.tbl.Length() == 0 {
				OpenError("No conversation selected.", app)
				return
			}
			pos := conv1.tbl.Pos()

			cmodel := &convsModelWithRow{
				model: conv1.model,
				row:   pos,
			}

			filter := ComputeConvFilterOp(dirOp, w.filterSelectedIndex, cmodel, FilterWidget.Value())

			FilterWidget.SetValue(filter, app)

			if w.filterPrep {
				// Don't run the filter, just add to the displayfilter widget. Leave focus there
				w.focusOnFilter = true
				OpenMessage("Display filter prepared.", appView, app)
			} else {
				RequestNewFilter(filter, app)
				w.displayFilter = filter
				OpenMessage("Display filter applied.", appView, app)
				w.ReloadNeeded()
			}
		}
	}
}

type IFilterModel interface {
	GetAFilter(Direction) string
	GetBFilter(Direction) string
}

func ComputeConvFilterOp(dirOp FilterMask, comb FilterCombinator, model IFilterModel, curFilter string) string {
	var filter string
	switch dirOp {
	case AtfB:
		filter = fmt.Sprintf("%s && %s", model.GetAFilter(Any), model.GetBFilter(Any))
	case AtB:
		filter = fmt.Sprintf("%s && %s", model.GetAFilter(From), model.GetBFilter(To))
	case BtA:
		filter = fmt.Sprintf("%s && %s", model.GetBFilter(From), model.GetAFilter(To))
	case AtfAny:
		filter = model.GetAFilter(Any)
	case AtAny:
		filter = model.GetAFilter(From)
	case AnytA:
		filter = model.GetAFilter(To)
	case AnytfB:
		filter = model.GetBFilter(Any)
	case AnytB:
		filter = model.GetBFilter(To)
	case BtAny:
		filter = model.GetBFilter(From)
	}

	return ComputeFilterCombOp(comb, filter, curFilter)
}

func ComputeFilterCombOp(comb FilterCombinator, newFilter string, curFilter string) string {
	switch comb {
	case NotSelected:
		newFilter = fmt.Sprintf("!(%s)", newFilter)
	case AndSelected:
		if curFilter != "" {
			newFilter = fmt.Sprintf("%s && (%s)", curFilter, newFilter)
		} else {
			newFilter = fmt.Sprintf("%s", newFilter)
		}
	case OrSelected:
		if curFilter != "" {
			newFilter = fmt.Sprintf("%s || (%s)", curFilter, newFilter)
		} else {
			newFilter = fmt.Sprintf("%s", newFilter)
		}
	case AndNotSelected:
		if curFilter != "" {
			newFilter = fmt.Sprintf("%s && !(%s)", curFilter, newFilter)
		} else {
			newFilter = fmt.Sprintf("!%s", newFilter)
		}
	case OrNotSelected:
		if curFilter != "" {
			newFilter = fmt.Sprintf("%s || !(%s)", curFilter, newFilter)
		} else {
			newFilter = fmt.Sprintf("!%s", newFilter)
		}
	}

	return newFilter
}

func (w *ConvsUiWidget) OnCancel(app gowid.IApp) {
	for _, cw := range w.convs {
		cw.IWidget = cw.cancelledWidget
	}
}

func (w *ConvsUiWidget) OnData(data string, app gowid.IApp) {
	var hdrs []string
	var wids []gowid.IWidgetDimension
	var comps []table.ICompare
	var cur string
	var next string
	var ports bool = false

	var (
		addra      string
		porta      string
		addrb      string
		portb      string
		framesto   string
		bytesto    string
		framesfrom string
		bytesfrom  string
		frames     string
		bytes      string
		start      string
		durn       string
	)

	var datas [][]string

	saveConversation := func(cur string) {
		tblModel := table.NewSimpleModel(hdrs, datas, table.SimpleOptions{
			Comparators: comps,
			Style: table.StyleOptions{
				HorizontalSeparator: nil,
				TableSeparator:      divider.NewUnicode(),
				VerticalSeparator:   nil,
				CellStyleProvided:   true,
				CellStyleSelected:   gowid.MakePaletteRef("packet-list-cell-selected"),
				CellStyleFocus:      gowid.MakePaletteRef("packet-list-cell-focus"),
				HeaderStyleProvided: true,
				HeaderStyleFocus:    gowid.MakePaletteRef("packet-list-cell-focus"),
			},
			Layout: table.LayoutOptions{
				Widths: wids,
			},
		})

		ptblModel := psmlmodel.New(
			tblModel,
			gowid.MakePaletteRef("packet-list-row-focus"),
		)

		if currentShortName, ok := convs.OfficialNameToType[cur]; ok {

			model := &ConvsModel{
				Model: ptblModel,
				proto: convTypes[currentShortName],
			}

			tbl := &table.BoundedWidget{
				Widget: table.New(model),
			}

			boundedTbl := NewRowFocusTableWidget(
				tbl,
				"packet-list-row-selected",
				"packet-list-row-focus",
			)

			var _ list.IWalker = boundedTbl
			var _ gowid.IWidget = boundedTbl
			var _ table.IBoundedModel = tblModel

			w.convs[w.tabIndex[currentShortName]].IWidget = appkeys.New(
				enableselected.New(
					withscrollbar.New(
						scrollabletable.New(
							copymodetable.New(
								boundedTbl,
								CsvTableCopier{hdrs, datas},
								CsvTableCopier{hdrs, datas},
								"convstable",
								copyModePalette{},
							),
						),
						withscrollbar.Options{
							HideIfContentFits: true,
						},
					),
				),
				tableutil.GotoHandler(&tableutil.GoToAdapter{
					BoundedWidget: tbl,
					KeyState:      &keyState,
				}),
			)

			w.convs[w.tabIndex[currentShortName]].tbl = tbl
			w.convs[w.tabIndex[currentShortName]].model = model
			w.buttonLabels[currentShortName].SetText(fmt.Sprintf(" %s (%d) ", cur, len(datas)), app)
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(data))
	var n int
	var err error
	for scanner.Scan() {
		line := scanner.Text()
		r := strings.NewReader(line)
		n, err = fmt.Fscanf(r, "%s Conversations", &next)
		if err == nil && n == 1 {
			if cur != "" {
				saveConversation(cur)
			}

			datas = make([][]string, 0)
			cur = next

			ports = termshark.StringInSlice(cur, []string{"UDP", "TCP"})
			ipv6 := (cur == "IPv6")

			var addrComp table.ICompare = termshark.IPCompare{}
			if termshark.StringInSlice(cur, []string{"Ethernet"}) {
				addrComp = termshark.MACCompare{}
			}

			var convComp table.ICompare = termshark.ConvPktsCompare{}

			if ports {
				hdrs = []string{
					"Addr A",
					"Port A",
					"Addr B",
					"Port B",
					"Pkts",
					"Bytes",
					"Pkts A→B",
					"Bytes A→B",
					"Pkts B→A",
					"Bytes B→A",
					"Start",
					"Durn",
				}
				wids = []gowid.IWidgetDimension{
					weightupto(400, 32), // addra
					weightupto(200, 7),  // port
					weightupto(400, 32), // addrb
					weightupto(200, 7),  // port
					weightupto(200, 8),  // pkts
					weightupto(200, 10),
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(500, 14), // start
					weightupto(200, 8),  // durn
				}
				comps = []table.ICompare{
					addrComp,
					table.IntCompare{},
					addrComp,
					table.IntCompare{},
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.FloatCompare{},
					table.FloatCompare{},
				}

			} else {
				hdrs = []string{
					"Addr A",
					"Addr B",
					"Pkts",
					"Bytes",
					"Pkts A→B",
					"Bytes A→B",
					"Pkts B→A",
					"Bytes B→A",
					"Start",
					"Durn",
				}

				wids = []gowid.IWidgetDimension{
					weightupto(400, 32), // addra
					weightupto(400, 32), // addrb
					weightupto(200, 8),  // pkts
					weightupto(200, 10),
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(200, 12), // pkts a -> b
					weightupto(200, 12), // bytes a -> b
					weightupto(500, 14), // start
					weightupto(200, 10), // durn
				}
				if ipv6 {
					wids[0] = weightupto(500, 42)
					wids[1] = weightupto(500, 42)
				}
				comps = []table.ICompare{
					addrComp,
					addrComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.IntCompare{},
					convComp,
					table.FloatCompare{},
					table.FloatCompare{},
				}

			}

			continue
		}

		line = strings.Replace(line, " bytes", "", -1)
		line = strings.Replace(line, "bytes", "", -1)
		line = strings.Replace(line, " kB", "kB", -1)
		line = strings.Replace(line, " MB", "MB", -1)
		r = strings.NewReader(line)
		n, err = fmt.Fscanf(r, "%s <-> %s %s %s %s %s %s %s %s %s",
			&addra,
			&addrb,
			&framesto,
			&bytesto,
			&framesfrom,
			&bytesfrom,
			&frames,
			&bytes,
			&start,
			&durn,
		)
		if err == nil && n == 10 {
			bytesto = strings.Replace(bytesto, "kB", " kB", -1)
			bytesfrom = strings.Replace(bytesfrom, "kB", " kB", -1)
			bytes = strings.Replace(bytes, "kB", " kB", -1)
			bytesto = strings.Replace(bytesto, "MB", " MB", -1)
			bytesfrom = strings.Replace(bytesfrom, "MB", " MB", -1)
			bytes = strings.Replace(bytes, "MB", " MB", -1)
			if ports {
				pa := strings.Split(addra, ":")
				pb := strings.Split(addrb, ":")
				if len(pa) == 2 && len(pb) == 2 {
					addra = pa[0]
					porta = pa[1]
					addrb = pb[0]
					portb = pb[1]
					datas = append(datas, []string{addra, porta, addrb, portb, framesto, bytesto, framesfrom, bytesfrom, frames, bytes, start, durn})
				}
			} else {
				datas = append(datas, []string{addra, addrb, framesto, bytesto, framesfrom, bytesfrom, frames, bytes, start, durn})
			}
		}
	}

	saveConversation(cur)
}

//======================================================================

type oneConvWidget struct {
	gowid.IWidget
	ctype            string
	pleaseWaitWidget gowid.IWidget
	cancelledWidget  gowid.IWidget
	model            *ConvsModel
	tbl              *table.BoundedWidget
}

func newOneConv(ctype string) *oneConvWidget {
	pleaseWaitWidget := vpadding.New(
		hpadding.New(
			text.New(fmt.Sprintf("Please wait for %s", ctype)),
			gowid.HAlignMiddle{},
			gowid.RenderFixed{},
		),
		gowid.VAlignMiddle{},
		gowid.RenderFlow{},
	)

	cancelledWidget := text.New("Conversation load was cancelled.")

	res := &oneConvWidget{
		IWidget:          pleaseWaitWidget,
		ctype:            ctype,
		pleaseWaitWidget: pleaseWaitWidget,
		cancelledWidget:  cancelledWidget,
	}

	return res
}

//======================================================================

type CsvTableCopier struct {
	hdrs []string
	data [][]string
}

func (c CsvTableCopier) CopyRow(id table.RowId) []gowid.ICopyResult {
	row := strings.Join(c.data[id], ",")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy conversation",
			Val:  row,
		},
	}
}

func (c CsvTableCopier) CopyTable() []gowid.ICopyResult {
	res := make([]string, 0, len(c.data)+1)

	res = append(res, strings.Join(c.hdrs, ","))
	for _, d := range c.data {
		res = append(res, strings.Join(d, ","))
	}

	prt := strings.Join(res, "\n")

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Copy all",
			Val:  prt,
		},
	}
}

var _ copymodetable.IRowCopier = CsvTableCopier{}
var _ copymodetable.ITableCopier = CsvTableCopier{}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
