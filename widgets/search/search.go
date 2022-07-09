// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package search provides termshark's search widget including the various
// drop down menus to control the type of search to be issued.
package search

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/disable"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/fields"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/ifwidget"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

var (
	// map internal names to user-visible names
	searchTypeMap = map[string]string{
		"filter": "Filter",
		"hex":    "Hex",
		"string": "String",
		"regex":  "Regex",
	}

	// map internal names to user-visible names
	searchTargetMap = map[string]string{
		"bytes":   "Pkt Bytes",
		"list":    "Pkt List",
		"details": "Pkt Details",
	}
)

type INeedle interface {
	Search(data string) int
}

//======================================================================

// simpleTerm represents a string that can be searched-for in provided data.
type simpleTerm string

func (s simpleTerm) String() string {
	return string(s)
}

func (s simpleTerm) Search(data string) int {
	return strings.Index(data, string(s))

}

var _ fmt.Stringer = simpleTerm("")
var _ INeedle = simpleTerm("")

//======================================================================

// stringTerm represents a string that can be searched-for in provided data with a toggle to control whether
// or not the search is case-sensitive.
type stringTerm struct {
	term          simpleTerm
	ciTerm        simpleTerm
	caseSensitive bool
}

func newStringTerm(t string, cs bool) stringTerm {
	return stringTerm{
		term:          simpleTerm(t),
		ciTerm:        simpleTerm(strings.ToUpper(t)),
		caseSensitive: cs,
	}
}

func (t stringTerm) CaseSensitive() bool {
	return t.caseSensitive
}

func (s stringTerm) Search(data string) int {
	if s.caseSensitive {
		return s.term.Search(data)
	} else {
		return s.ciTerm.Search(strings.ToUpper(data))
	}
}

//======================================================================

// hexTerm holds a string that represents a bytes to be searched for in binary data.  The syntax follows
// Wireshark - each byte is given as two ASCII characters in the range [0-9a-fA-F], and a sequence of bytes
// is the concatenation of these two characters e.g. "54AD090f" is a 4-byte search.
type hexTerm struct {
	user  string
	bytes []byte
}

func newHexTerm(user string) hexTerm {
	return hexTerm{
		user:  user,
		bytes: hexTermToBytes(user),
	}
}

func hexToByte(b byte) int {
	r := rune(b)
	switch {
	case r >= 'a' && r <= 'f':
		return int(r + 10 - 'a')
	case r >= 'A' && r <= 'F':
		return int(r + 10 - 'A')
	case r >= '0' && r <= '9':
		return int(r - '0')
	default:
		panic(nil)
	}
}

func hexTermToBytes(s string) []byte {
	res := make([]byte, 0, 16)
	if (len(s)/2)*2 != len(s) {
		panic(nil)
	}
	for i := 0; i < len(s); i += 2 {
		res = append(res, byte(hexToByte(s[i])<<4+hexToByte(s[i+1])))
	}
	return res
}

func (s hexTerm) Search(data string) int {
	return bytes.Index([]byte(data), s.bytes)
}

var _ INeedle = hexTerm{}

//======================================================================

// regexTerm represents a regex to be searched-for in packet data, with a flag that determines
// whether or not the search is case-sensitive.
type regexTerm struct {
	re            *regexp.Regexp
	cire          *regexp.Regexp
	caseSensitive bool
}

func newRegexTerm(rest string, cs bool) (regexTerm, error) {
	re, err := regexp.Compile(rest)
	if err != nil {
		return regexTerm{}, err
	}
	re2, err := regexp.Compile("(?i)" + rest)
	if err != nil {
		return regexTerm{}, err
	}
	return regexTerm{re: re, cire: re2, caseSensitive: cs}, nil
}

func (s regexTerm) Search(data string) int {
	var res []int
	if s.caseSensitive {
		res = s.re.FindStringIndex(data)
	} else {
		res = s.cire.FindStringIndex(data)
	}
	if res == nil {
		return -1
	} else {
		return res[0]
	}
}

var _ INeedle = regexTerm{}

//======================================================================

type IRequestStop interface {
	RequestStop(app gowid.IApp)
}

type IErrorHandler interface {
	OnError(err error, app gowid.IApp)
}

type IResult interface {
	PacketNumber() int
}

type Result struct {
	Interrupted  bool
	Success      bool
	ErrorForUser error
	Position     interface{}
}

type IntermediateResult struct {
	Res      Result
	ResumeAt IResult
}

type IAlgorithm interface {
	SearchPackets(term INeedle, cb ICallbacks, app gowid.IApp)
}

// ICallbacks is intended to be a callback issued when the Find invocation yields a
// result of some kind
type ICallbacks interface {
	Reset(app gowid.IApp) // Intended to make things ready for next "Find" invocation
	StartingPosition() (interface{}, error)
	SearchPacketsFrom(from interface{}, start interface{}, term INeedle, app gowid.IApp)
	SearchPacketsResult(res Result, app gowid.IApp)
	RequestStop(app gowid.IApp)
	OnTick(app gowid.IApp)
	OnError(err error, app gowid.IApp)
}

var fixed gowid.RenderFixed

//======================================================================

// Widget represents a composite UI element for driving packet search operations. It comprises a menu
// allowing the type of data to be searched - PSML, PDML or raw bytes; a menu determining the search
// method - string, regex, hex or filter; the input field for the search, and a button to start the
// search. Note that the filter search is a special case - the search value is used as a display filter
// to select packets from the current source, rather than for searching within packet data.
type Widget struct {
	gowid.IWidget
	*gowid.Callbacks
	filterHolder    *holder.Widget
	filt            *filter.Widget
	menuOpener      menu.IOpener
	completer       fields.IPrefixCompleter
	cols            *columns.Widget
	findBtn         *disable.Widget
	searchTargetBtn *button.Widget
	dataBtn         *button.Widget
	validator       filter.IValidator
	errHandler      IErrorHandler
	alg             IAlgorithm
	listFn          func() ICallbacks
	structFn        func() ICallbacks
	bytesFn         func() ICallbacks
	filterFn        func() ICallbacks
	listAlg         ICallbacks
	structAlg       ICallbacks
	bytesAlg        ICallbacks
	filtAlg         ICallbacks
	currentAlg      ICallbacks // Which search algorithm to use - psml, pdml, hex, filter
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.IFocus = (*Widget)(nil)
var _ gowid.ICompositeMultipleFocus = (*Widget)(nil) // for SetFocusPath support
var _ gowid.IPreferedPosition = (*Widget)(nil)

//======================================================================

type enableSearchButton struct {
	ICallbacks
	btn *disable.Widget
}

func (f enableSearchButton) SearchPacketsResult(res Result, app gowid.IApp) {
	f.ICallbacks.SearchPacketsResult(res, app)
	f.btn.Enable()
}

func (f enableSearchButton) OnError(err error, app gowid.IApp) {
	f.ICallbacks.OnError(err, app)
	f.btn.Enable()
}

//======================================================================

func weight(n int) gowid.RenderWithWeight {
	return gowid.RenderWithWeight{W: n}
}

func units(n int) gowid.RenderWithUnits {
	return gowid.RenderWithUnits{U: n}
}

func getSearchType() string {
	res := profiles.ConfString("main.search-type", "filter")
	if _, ok := searchTypeMap[res]; !ok {
		res = "filter"
	}
	return res
}

func getSearchTarget() string {
	res := profiles.ConfString("main.search-target", "list")
	if _, ok := searchTargetMap[res]; !ok {
		res = "list"
	}
	return res
}

func getValidator() filter.IValidator {
	var validator filter.IValidator
	s2 := getSearchType()
	switch s2 {
	case "filter":
		validator = &filter.DisplayFilterValidator{}
	case "hex":
		validator = &HexSearchValidator{}
	case "string":
		validator = &StringSearchValidator{}
	case "regex":
		validator = &RegexSearchValidator{}
	default:
		panic(nil)
	}
	return validator
}

func New(alg IAlgorithm,
	searchPktList func() ICallbacks,
	searchPktStruct func() ICallbacks,
	searchPktDetails func() ICallbacks,
	searchByFilter func() ICallbacks,
	men menu.IOpener,
	comp fields.IPrefixCompleter,
	errHandler IErrorHandler) *Widget {

	res := &Widget{
		alg:        alg,
		listFn:     searchPktList,
		structFn:   searchPktStruct,
		bytesFn:    searchPktDetails,
		filterFn:   searchByFilter,
		listAlg:    searchPktList(),
		structAlg:  searchPktStruct(),
		bytesAlg:   searchPktDetails(),
		filtAlg:    searchByFilter(),
		validator:  getValidator(),
		errHandler: errHandler,
		menuOpener: men,
		completer:  comp,
	}

	colSpaceW := hpadding.New(
		fill.New(' '),
		gowid.HAlignLeft{},
		gowid.RenderWithUnits{U: 1},
	)

	colSpace := &gowid.ContainerWidget{
		IWidget: colSpaceW,
		D:       units(1),
	}

	searchTypeB := button.New(text.New(searchTypeMap[getSearchType()]))
	searchTypeBtn := disable.NewEnabled(
		clicktracker.New(
			styled.NewExt(
				searchTypeB,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
		),
	)

	mymenu := buildSearchTypeMenu(searchTypeB, men, res)

	searchTypeBtnSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	searchTypeB.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		if !men.OpenMenu(mymenu, searchTypeBtnSite, app) {
			// Close if already open
			men.CloseMenu(mymenu, app)
		}
	}))

	findB := button.New(text.New("Find"))
	res.findBtn = disable.NewDisabled(
		clicktracker.New(
			styled.NewExt(
				findB,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
		),
	)

	// Start disableINeedleter is empty and we know that's invalid. This should be
	// enforced somewhere, via some sort of data-binding.
	findB.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		res.invokeSearch(app)
	}))

	// Make sure that when the final result of the search is issued, the button
	// is re-enabled
	res.listAlg = enableSearchButton{ICallbacks: res.listAlg, btn: res.findBtn}
	res.structAlg = enableSearchButton{ICallbacks: res.structAlg, btn: res.findBtn}
	res.bytesAlg = enableSearchButton{ICallbacks: res.bytesAlg, btn: res.findBtn}
	res.filtAlg = enableSearchButton{ICallbacks: res.filtAlg, btn: res.findBtn}

	dataB := button.New(text.New("Wait..."))
	dataBtn := disable.NewEnabled(
		clicktracker.New(
			styled.NewExt(
				dataB,
				gowid.MakePaletteRef("button"),
				gowid.MakePaletteRef("button-focus"),
			),
		),
	)

	res.searchTargetBtn = dataB
	res.searchTargetBtn.SetSubWidget(text.New(searchTargetMap[getSearchTarget()]), nil)

	// Do after res.searchTargetBtn set up
	res.updateSearchTargetFromConf(nil)

	mymenu2 := buildSearchTargetMenu(dataB, men, res)

	dataBtnSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	dataB.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		if !men.OpenMenu(mymenu2, dataBtnSite, app) {
			// Close if already open
			men.CloseMenu(mymenu2, app)
		}
		//men.OpenMenu(mymenu2, dataBtnSite, app)
	}))
	res.dataBtn = dataB

	caseCheck := checkbox.New(res.CaseSensitive())
	caseCheck.OnClick(gowid.WidgetCallback{"cb", func(app gowid.IApp, _ gowid.IWidget) {
		res.SetCaseSensitive(caseCheck.IsChecked())
	}})

	caseLabel := text.New(" Case Sens ")
	caseW := hpadding.New(
		columns.NewFixed(caseCheck, caseLabel),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	selectiveCols := hpadding.New(
		columns.NewFixed(dataBtnSite, dataBtn, colSpace, caseW),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	res.filterHolder = holder.New(null.New())

	res.setFilter(getValidator(), res.getCompleter(), nil)

	// Will only be enabled to click if filter is valid

	selcols := ifwidget.New(
		selectiveCols,
		null.New(),
		func() bool {
			st := getSearchType()
			return st == "string" || st == "regex"
		},
	)

	// If this structure changes, see [[focusOnFilter]]
	res.cols = columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: text.New("Find:"),
			D:       fixed,
		},
		colSpace,
		&gowid.ContainerWidget{
			IWidget: selcols,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: searchTypeBtnSite,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: searchTypeBtn,
			D:       fixed,
		},
		colSpace,
		&gowid.ContainerWidget{
			IWidget: res.filterHolder,
			D:       weight(1),
		},
		&gowid.ContainerWidget{
			IWidget: res.findBtn,
			D:       fixed,
		},
		colSpace,
	})

	res.IWidget = res.cols

	return res
}

func (w *Widget) invokeSearch(app gowid.IApp) {
	var searchTerm INeedle
	switch w.validator.(type) {
	case *filter.DisplayFilterValidator:
		searchTerm = simpleTerm(w.filt.Value())
	case *HexSearchValidator:
		searchTerm = newHexTerm(w.filt.Value())
	case *StringSearchValidator:
		searchTerm = newStringTerm(w.filt.Value(), w.CaseSensitive())
	case *RegexSearchValidator:
		var err error
		searchTerm, err = newRegexTerm(w.filt.Value(), w.CaseSensitive())
		if err != nil {
			w.errHandler.OnError(fmt.Errorf("Could not validate: %w", err), app)
			return
		}
	default:
		panic(nil)
	}

	w.findBtn.Disable()
	w.alg.SearchPackets(searchTerm, w.currentAlg, app)
}

func (w *Widget) getCompleter() fields.IPrefixCompleter {
	var completer fields.IPrefixCompleter
	s2 := getSearchType()
	switch s2 {
	case "filter":
		completer = w.completer
	}
	return completer
}

// <<focusOnFilter>>
func (w *Widget) focusOnFilter(app gowid.IApp) {
	w.cols.SetFocus(app, 6)
}

func (w *Widget) setFilter(validator filter.IValidator, completer fields.IPrefixCompleter, app gowid.IApp) {
	filt := filter.New("searchfilter", filter.Options{
		MenuOpener: w.menuOpener,
		Completer:  completer,
		Position:   filter.Below,
		Validator:  validator,
	})

	filt.OnValid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		w.findBtn.Enable()
	}))
	filt.OnInvalid(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		w.findBtn.Disable()
	}))

	validFilterCb := gowid.MakeWidgetCallback("cb", func(app gowid.IApp, _ gowid.IWidget) {
		w.invokeSearch(app)
	})

	filt.OnSubmit(validFilterCb)

	w.filt = filt
	w.filterHolder.SetSubWidget(filt, app)
}

func (w *Widget) SetValue(val string, app gowid.IApp) {
	w.filt.SetValue(val, app)
}

func (w *Widget) Value() string {
	return w.filt.Value()
}

func (w *Widget) CaseSensitive() bool {
	return profiles.ConfBool("main.search-case-sensitive", false)
}

func (w *Widget) SetCaseSensitive(val bool) {
	profiles.SetConf("main.search-case-sensitive", val)
}

func (w *Widget) Open(app gowid.IApp) {
	filt := filter.New("searchfilter", filter.Options{
		MenuOpener: w.menuOpener,
		Completer:  w.completer,
		Position:   filter.Below,
		Validator:  getValidator(),
	})
	w.filt = filt
	w.filterHolder.SetSubWidget(filt, app)
}

func (w *Widget) Close(app gowid.IApp) error {
	// Stop any search going on
	w.currentAlg.RequestStop(app)
	filt := w.filterHolder.SubWidget().(*filter.Widget)
	return filt.Close()
}

func (w *Widget) Clear(app gowid.IApp) {
	w.currentAlg.RequestStop(app)

	// Throw away all search state, cached results
	w.listAlg = w.listFn()
	w.bytesAlg = w.bytesFn()
	w.structAlg = w.structFn()
	w.filtAlg = w.filterFn()

	w.listAlg = enableSearchButton{ICallbacks: w.listAlg, btn: w.findBtn}
	w.structAlg = enableSearchButton{ICallbacks: w.structAlg, btn: w.findBtn}
	w.bytesAlg = enableSearchButton{ICallbacks: w.bytesAlg, btn: w.findBtn}
	w.filtAlg = enableSearchButton{ICallbacks: w.filtAlg, btn: w.findBtn}

	w.updateSearchTargetFromConf(app)
}

func (w *Widget) FocusIsOnFilter() bool {
	return w.cols.Focus() == 6
}

func (w *Widget) Focus() int {
	return w.cols.Focus()
}

func (w *Widget) SetFocus(app gowid.IApp, i int) {
	w.cols.SetFocus(app, i)
}

func (w *Widget) SubWidgets() []gowid.IWidget {
	return w.cols.SubWidgets()
}

func (w *Widget) GetPreferedPosition() gwutil.IntOption {
	return w.cols.GetPreferedPosition()
}

func (w *Widget) SetPreferedPosition(cols int, app gowid.IApp) {
	w.cols.SetPreferedPosition(cols, app)
}

//======================================================================

type indirect struct {
	*holder.Widget
}

func buildSearchTypeMenu(btn *button.Widget, men menu.IOpener, res *Widget) *menu.Widget {
	searchTypeMenu1Holder := &indirect{}

	searchTypeMenu := menu.New("searchtype", searchTypeMenu1Holder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	menuItems := make([]menuutil.SimpleMenuItem, 0)

	for i, stype_ := range []string{
		"filter",
		"hex",
		"string",
		"regex",
	} {
		stype := stype_
		menuItems = append(menuItems,
			menuutil.SimpleMenuItem{
				Txt: searchTypeMap[stype],
				Key: gowid.MakeKey('1' + rune(i)),
				CB: func(app gowid.IApp, _ gowid.IWidget) {
					btn.SetSubWidget(text.New(searchTypeMap[stype]), app)

					// Save the default search type
					profiles.SetConf("main.search-type", stype)

					res.validator = getValidator()

					// Save the old value
					fval := res.Value()

					res.Close(app)

					// Use the new validating filter
					res.setFilter(getValidator(), res.getCompleter(), app)

					// Update the validity for the current value - maybe it's not valid with the new filter
					res.SetValue(fval, app)

					switch stype {
					case "hex":
						profiles.SetConf("main.search-target", "bytes")
					}

					// read main.search-type and adjust which search algorithm to use
					res.updateSearchTargetFromConf(app)

					// This is probably what the user will do next
					res.focusOnFilter(app)

					men.CloseMenu(searchTypeMenu, app)
				},
			},
		)
	}

	lb, _ := menuutil.MakeMenuWithHotKeys(menuItems, nil)

	searchTypeMenu1Holder.Widget = holder.New(lb)

	return searchTypeMenu
}

//======================================================================

func (w *Widget) updateSearchTargetFromConf(app gowid.IApp) {

	sAlg := profiles.ConfString("main.search-type", "filter")
	if sAlg != "filter" && sAlg != "hex" {
		sAlg = profiles.ConfString("main.search-target", "list")
	}

	switch sAlg {
	case "list":
		w.currentAlg = w.listAlg
	case "details":
		w.currentAlg = w.structAlg
	case "bytes":
		w.currentAlg = w.bytesAlg
	case "hex":
		w.currentAlg = w.bytesAlg
	case "filter":
		w.currentAlg = w.filtAlg
	default:
		panic(nil)
	}
}

//======================================================================

func buildSearchTargetMenu(btn *button.Widget, men menu.IOpener, res *Widget) *menu.Widget {
	dataMenu1Holder := &indirect{}

	dataMenu := menu.New("datatype", dataMenu1Holder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	menuItems := make([]menuutil.SimpleMenuItem, 0)

	for i, target_ := range []string{
		"list",
		"details",
		"bytes",
	} {
		target := target_
		menuItems = append(menuItems,
			menuutil.SimpleMenuItem{
				Txt: searchTargetMap[target],
				Key: gowid.MakeKey('1' + rune(i)),
				CB: func(app gowid.IApp, _ gowid.IWidget) {

					profiles.SetConf("main.search-target", target)

					btn.SetSubWidget(text.New(searchTargetMap[target]), app)

					res.updateSearchTargetFromConf(app)

					men.CloseMenu(dataMenu, app)
				},
			},
		)
	}

	lb, _ := menuutil.MakeMenuWithHotKeys(menuItems, nil)

	dataMenu1Holder.Widget = holder.New(lb)

	return dataMenu
}

//======================================================================

type RegexSearchValidator struct {
	Valid    filter.IValidateCB
	Invalid  filter.IValidateCB
	KilledCB filter.IValidateCB
	EmptyCB  filter.IValidateCB
}

var _ filter.IValidator = (*RegexSearchValidator)(nil)

func (f *RegexSearchValidator) SetValid(cb filter.IValidateCB) {
	f.Valid = cb
}
func (f *RegexSearchValidator) SetInvalid(cb filter.IValidateCB) {
	f.Invalid = cb
}
func (f *RegexSearchValidator) SetKilled(cb filter.IValidateCB) {
	f.KilledCB = cb
}
func (f *RegexSearchValidator) SetEmpty(cb filter.IValidateCB) {
	f.EmptyCB = cb
}

func (f *RegexSearchValidator) Kill() (bool, error) {
	return true, nil
}

func (f *RegexSearchValidator) Validate(filter string) {
	if filter == "" {
		if f.EmptyCB != nil {
			f.EmptyCB.Call(filter)
		}
		return
	}
	_, err := regexp.Compile(filter)

	if err == nil {
		if f.Valid != nil {
			f.Valid.Call(filter)
		}
	} else {
		if f.Invalid != nil {
			f.Invalid.Call(filter)
		}
	}
}

//======================================================================

type StringSearchValidator struct {
	Valid    filter.IValidateCB
	Invalid  filter.IValidateCB
	KilledCB filter.IValidateCB
	EmptyCB  filter.IValidateCB
}

var _ filter.IValidator = (*StringSearchValidator)(nil)

func (f *StringSearchValidator) SetValid(cb filter.IValidateCB) {
	f.Valid = cb
}
func (f *StringSearchValidator) SetInvalid(cb filter.IValidateCB) {
	f.Invalid = cb
}
func (f *StringSearchValidator) SetKilled(cb filter.IValidateCB) {
	f.KilledCB = cb
}
func (f *StringSearchValidator) SetEmpty(cb filter.IValidateCB) {
	f.EmptyCB = cb
}

func (f *StringSearchValidator) Kill() (bool, error) {
	return true, nil
}

func (f *StringSearchValidator) Validate(filter string) {
	if filter == "" {
		if f.EmptyCB != nil {
			f.EmptyCB.Call(filter)
		}
		return
	}

	if f.Valid != nil {
		f.Valid.Call(filter)
	}
}

//======================================================================

var hexre *regexp.Regexp

func init() {
	hexre = regexp.MustCompile(`^([0-9a-fA-F]{2})+$`) // do each line
}

type HexSearchValidator struct {
	Valid    filter.IValidateCB
	Invalid  filter.IValidateCB
	KilledCB filter.IValidateCB
	EmptyCB  filter.IValidateCB
}

var _ filter.IValidator = (*HexSearchValidator)(nil)

func (f *HexSearchValidator) SetValid(cb filter.IValidateCB) {
	f.Valid = cb
}
func (f *HexSearchValidator) SetInvalid(cb filter.IValidateCB) {
	f.Invalid = cb
}
func (f *HexSearchValidator) SetKilled(cb filter.IValidateCB) {
	f.KilledCB = cb
}
func (f *HexSearchValidator) SetEmpty(cb filter.IValidateCB) {
	f.EmptyCB = cb
}

func (f *HexSearchValidator) Kill() (bool, error) {
	return true, nil
}

func (f *HexSearchValidator) Validate(filter string) {
	if filter == "" {
		if f.EmptyCB != nil {
			f.EmptyCB.Call(filter)
		}
		return
	}

	if hexre.MatchString(filter) {
		if f.Valid != nil {
			f.Valid.Call(filter)
		}
	} else {
		if f.Invalid != nil {
			f.Invalid.Call(filter)
		}
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
