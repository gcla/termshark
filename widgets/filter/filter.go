// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package filter prpvides a termshark-specific edit widget which changes
// color according to the validity of its input, and which activates a
// drop-down menu of possible completions for the term at point.
package filter

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/vim"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/cellmod"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gdamore/tcell"
)

//======================================================================

// This is a debugging aid - I use it to ensure goroutines stop as expected. If they don't
// the main program will hang at termination.
var Goroutinewg *sync.WaitGroup

type filtStruct struct {
	txt string
	app gowid.IApp
}

type Widget struct {
	wrapped              gowid.IWidget
	opts                 Options
	ed                   *edit.Widget     // what the user types into - wrapped by validity styling
	dropDown             *menu.Widget     // the menu of possible completions
	dropDownSite         *menu.SiteWidget // where in this widget structure the drop down is rendered
	validitySite         *holder.Widget   // the widget swaps out the contents of this placeholder on validity changes
	valid                gowid.IWidget    // what to display when the filter value is valid
	invalid              gowid.IWidget    // what to display when the filter value is invalid
	intermediate         gowid.IWidget    // what to display when the filter value's validity is being determined
	edCtx                context.Context
	edCancelFn           context.CancelFunc
	edCtxLock            sync.Mutex
	fields               termshark.IPrefixCompleter // provides completions, given a prefix
	completionsList      *list.Widget               // the filter widget replaces the list walker when new completions are generated
	completionsActivator *activatorWidget           // used to disable focus going to drop down
	completions          []string                   // the current set of completions, used when rendering
	runthisfilterchan    chan *filtStruct
	filterchangedchan    chan *filtStruct
	quitchan             chan struct{}
	readytorunchan       chan struct{}
	temporarilyDisabled  *bool // set to true right after submitting a new filter, so the menu disappears
	enterPending         bool  // set to true if the user has hit enter; process if the filter goes to valid before another change. For slow validity processing.
	*gowid.Callbacks
	gowid.IsSelectable
}

var _ gowid.IWidget = (*Widget)(nil)
var _ io.Closer = (*Widget)(nil)

type IntermediateCB struct{}
type ValidCB struct{}
type InvalidCB struct{}
type SubmitCB struct{}

type Options struct {
	Completer      termshark.IPrefixCompleter
	MaxCompletions int
}

func New(opt Options) *Widget {
	res := &Widget{}

	ed := edit.New()
	ed.OnTextSet(gowid.WidgetCallback{"cb", func(app gowid.IApp, w gowid.IWidget) {
		// every time the filter changes, drop any pending enter - we don't want to
		// apply a filter to a stale value
		res.enterPending = false
	}})

	fixed := gowid.RenderFixed{}
	filterList := list.New(list.NewSimpleListWalker([]gowid.IWidget{}))
	filterActivator := &activatorWidget{
		IWidget: filterList,
	}

	if opt.MaxCompletions == 0 {
		opt.MaxCompletions = 20
	}

	menuListBox2 := styled.New(
		framed.NewUnicode(cellmod.Opaque(filterActivator)),
		gowid.MakePaletteRef("filter-menu"),
	)

	ign := make([]gowid.IKey, 0, len(vim.AllDownKeys)+len(vim.AllUpKeys))
	for _, k := range vim.AllDownKeys {
		if !termshark.KeyPressIsPrintable(gowid.Key(k)) {
			ign = append(ign, gowid.Key(k))
		}
	}
	for _, k := range vim.AllUpKeys {
		if !termshark.KeyPressIsPrintable(gowid.Key(k)) {
			ign = append(ign, gowid.Key(k))
		}
	}

	drop := menu.New("filter", menuListBox2, gowid.RenderWithUnits{U: opt.MaxCompletions + 2},
		menu.Options{
			IgnoreKeysProvided: true,
			IgnoreKeys:         ign,
			CloseKeysProvided:  true,
			CloseKeys:          []gowid.IKey{},
		},
	)

	site := menu.NewSite(menu.SiteOptions{
		YOffset: 1,
	})

	cb := gowid.NewCallbacks()

	onelineEd := appkeys.New(ed, handleEnter(cb, res), appkeys.Options{
		ApplyBefore: true,
	})

	valid := styled.New(onelineEd,
		gowid.MakePaletteRef("filter-valid"),
	)
	invalid := styled.New(onelineEd,
		gowid.MakePaletteRef("filter-invalid"),
	)
	intermediate := styled.New(onelineEd,
		gowid.MakePaletteRef("filter-intermediate"),
	)

	placeholder := holder.New(valid)

	var wrapped gowid.IWidget = columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{IWidget: site, D: fixed},
		&gowid.ContainerWidget{IWidget: placeholder, D: gowid.RenderWithWeight{W: 1}},
	})

	runthisfilterchan := make(chan *filtStruct)
	quitchan := make(chan struct{})
	readytorunchan := make(chan struct{})
	filterchangedchan := make(chan *filtStruct)

	*res = Widget{
		wrapped:              wrapped,
		opts:                 opt,
		ed:                   ed,
		dropDown:             drop,
		dropDownSite:         site,
		validitySite:         placeholder,
		valid:                valid,
		invalid:              invalid,
		intermediate:         intermediate,
		fields:               opt.Completer,
		completionsList:      filterList,
		completionsActivator: filterActivator,
		completions:          []string{},
		filterchangedchan:    filterchangedchan,
		runthisfilterchan:    runthisfilterchan,
		quitchan:             quitchan,
		readytorunchan:       readytorunchan,
		temporarilyDisabled:  new(bool),
		Callbacks:            cb,
	}

	validcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.valid, app)
				gowid.RunWidgetCallbacks(res.Callbacks, ValidCB{}, app, res)

				if res.enterPending {
					var dummy gowid.IWidget
					gowid.RunWidgetCallbacks(cb, SubmitCB{}, app, dummy)
					*res.temporarilyDisabled = true
					res.enterPending = false
				}

			}))
		},
	}

	invalidcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.invalid, app)
				gowid.RunWidgetCallbacks(res.Callbacks, InvalidCB{}, app, res)
				res.enterPending = false
			}))
		},
	}

	killedcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.intermediate, app)
				gowid.RunWidgetCallbacks(res.Callbacks, IntermediateCB{}, app, res)
				res.enterPending = false
			}))
		},
	}

	validator := Validator{
		Valid:    validcb,
		Invalid:  invalidcb,
		KilledCB: killedcb,
	}

	// Save up filter changes, send latest over when process is ready, discard ones in between
	termshark.TrackedGo(func() {
		send := false
		var latest *filtStruct
	CL2:
		for {
			if send && latest != nil {
				res.runthisfilterchan <- latest
				latest = nil
				send = false
			}
			select {
			// tshark process ready
			case <-res.quitchan:
				break CL2
			case <-res.readytorunchan:
				send = true
				// Sent by tshark process goroutine
			case fs := <-res.filterchangedchan:
				latest = fs
				// We're ready to run a new one, so kill any process that is in progress. Take care
				// because it might not have actually started yet!
				validator.Kill()
			}
		}
	}, Goroutinewg)

	// Every time it gets an event, it means run the process. Another goroutine takes care of consolidating
	// events. Stops when channel is closed
	termshark.TrackedGo(func() {
	CL:
		for {
			// Tell other goroutine we are ready for more - each time round the loop. This makes sure
			// we don't run more than one tshark process - it will get killed if a new filter should take
			// priority.
			select {
			case res.readytorunchan <- struct{}{}:
			case <-res.quitchan:
				break CL
			}

			select {
			case <-res.quitchan:
				break CL
			case fs := <-res.runthisfilterchan:
				validcb.App = fs.app
				invalidcb.App = fs.app
				killedcb.App = fs.app
				validator.Validate(fs.txt)
			}
		}
	}, Goroutinewg)

	ed.OnCursorPosSet(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, ew gowid.IWidget) {
		res.UpdateCompletions(app)
	})))

	ed.OnTextSet(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, ew gowid.IWidget) {
		res.UpdateCompletions(app)
	})))

	return res
}

type IValidateCB interface {
	Call(filter string)
}

type AppFilterCB func(gowid.IApp)

type ValidateCB struct {
	App gowid.IApp
	Fn  AppFilterCB
}

var _ IValidateCB = (*ValidateCB)(nil)

func (v *ValidateCB) Call(filter string) {
	v.Fn(v.App)
}

type Validator struct {
	Valid    IValidateCB
	Invalid  IValidateCB
	KilledCB IValidateCB
	Cmd      *exec.Cmd
}

func (f *Validator) Kill() (bool, error) {
	var err error
	var res bool
	if f.Cmd != nil {
		proc := f.Cmd.Process
		if proc != nil {
			res = true
			err = proc.Kill()
		}
	}
	return res, err
}

func (f *Validator) Validate(filter string) {
	var err error

	if filter != "" {
		f.Cmd = exec.Command(termshark.TSharkBin(), []string{"-Y", filter, "-r", termshark.CacheFile("empty.pcap")}...)
		err = f.Cmd.Run()
	}

	if err == nil {
		if f.Valid != nil {
			f.Valid.Call(filter)
		}
	} else {
		killed := true
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() == 2 {
					killed = false
				}
			}
		}
		if killed {
			if f.KilledCB != nil {
				f.KilledCB.Call(filter)
			}
		} else {
			if f.Invalid != nil {
				f.Invalid.Call(filter)
			}
		}
	}
}

type iFilterEnter interface {
	setDisabled()
	setEnterPending()
	isValid() bool
}

// if the filter is valid when enter is pressed, submit the SubmitCB callback. Those
// registered will be able to respond e.g. start handling the valid filter value.
func handleEnter(cb *gowid.Callbacks, fe iFilterEnter) appkeys.KeyInputFn {
	return func(evk *tcell.EventKey, app gowid.IApp) bool {
		handled := false
		switch evk.Key() {
		case tcell.KeyEnter:
			if fe.isValid() {
				var dummy gowid.IWidget
				gowid.RunWidgetCallbacks(cb, SubmitCB{}, app, dummy)
				fe.setDisabled()
			} else {
				fe.setEnterPending() // remember in case the filter goes valid shortly
			}
			handled = true
		}
		return handled
	}
}

func isValidFilterRune(r rune) bool {
	res := true
	switch {
	case unicode.IsLetter(r):
	case unicode.IsNumber(r):
	case r == '-':
	case r == '_':
	case r == '.':
	default:
		res = false
	}
	return res
}

func newMenuWidgets(ed *edit.Widget, completions []string) []gowid.IWidget {
	menu2Widgets := make([]gowid.IWidget, 0)

	fixed := gowid.RenderFixed{}
	for _, s := range completions {
		scopy := s

		clickme := button.New(
			hpadding.New(
				text.New(s),
				gowid.HAlignLeft{},
				gowid.RenderWithUnits{U: gwutil.Max(12, len(s))},
			),
			button.Options{
				Decoration:         button.BareDecoration,
				SelectKeysProvided: true,
				//SelectKeys:         []gowid.IKey{},
				SelectKeys: []gowid.IKey{gowid.MakeKeyExt(tcell.KeyEnter)},
			},
		)
		clickmeStyled := styled.NewInvertedFocus(clickme, gowid.MakePaletteRef("filter-menu"))
		clickme.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
			txt := ed.Text()
			end := ed.CursorPos()
			start := end
		Loop1:
			for {
				if start == 0 {
					break
				}
				start--
				if !isValidFilterRune(rune(txt[start])) {
					start++
					break Loop1
				}
			}
		Loop2:
			for {
				if end == len(txt) {
					break
				}
				if !isValidFilterRune(rune(txt[end])) {
					break Loop2
				}
				end++
			}
			ed.SetText(fmt.Sprintf("%s%s%s", txt[0:start], scopy, txt[end:len(txt)]), app)
			ed.SetCursorPos(len(txt[0:start])+len(scopy), app)

		}))
		cols := columns.New([]gowid.IContainerWidget{
			&gowid.ContainerWidget{IWidget: clickmeStyled, D: fixed},
		})

		menu2Widgets = append(menu2Widgets, cols)
	}

	return menu2Widgets
}

type fnCallback struct {
	app gowid.IApp
	fn  func([]string, gowid.IApp)
}

var _ termshark.IPrefixCompleterCallback = fnCallback{}

func (f fnCallback) Call(res []string) {
	f.fn(res, f.app)
}

func makeCompletions(comp termshark.IPrefixCompleter, txt string, max int, app gowid.IApp, fn func([]string, gowid.IApp)) {
	cb := fnCallback{
		app: app,
		fn: func(completions []string, app gowid.IApp) {
			completions = completions[0:gwutil.Min(max, len(completions))]
			fn(completions, app)
		},
	}
	comp.Completions(txt, cb)
}

func (w *Widget) setDisabled() {
	*w.temporarilyDisabled = true
}

func (w *Widget) setEnterPending() {
	w.enterPending = true
}

// isCurrentlyValid returns true if the current state of the filter is valid (green)
func (w *Widget) isValid() bool {
	return w.validitySite.SubWidget() == w.valid
}

// Start an asynchronous routine to update the drop-down menu with completion
// options. Runs on a small delay so it can be cancelled and restarted if the
// user is typing quickly.
func (w *Widget) UpdateCompletions(app gowid.IApp) {
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if w.ed.Text() != "" {
			w.validitySite.SetSubWidget(w.intermediate, app)
			gowid.RunWidgetCallbacks(w.Callbacks, IntermediateCB{}, app, w)
		}
	}))

	// UpdateCompletions can be called outside of the app goroutine, so we
	// need to protect the context
	w.edCtxLock.Lock()
	defer w.edCtxLock.Unlock()

	if w.edCancelFn != nil {
		w.edCancelFn()
	}
	w.edCtx, w.edCancelFn = context.WithCancel(context.Background())

	// don't kick things off right away in case user is typing fast
	go func(ctx context.Context) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Millisecond * 200):
			break
		}

		// Send the value to be run by tshark. This will kill any other one in progress.
		w.filterchangedchan <- &filtStruct{w.ed.Text(), app}

		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			_, y := app.GetScreen().Size()

			txt := w.ed.Text()
			end := w.ed.CursorPos()
			start := end
		Loop:
			for {
				if start == 0 {
					break
				}
				start--
				if !isValidFilterRune(rune(txt[start])) {
					start++
					break Loop
				}
			}

			makeCompletions(w.fields, txt[start:end], y, app, func(completions []string, app gowid.IApp) {
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					w.processCompletions(completions, app)
				}))
			})
		}))
	}(w.edCtx)
}

func (w *Widget) processCompletions(completions []string, app gowid.IApp) {
	max := w.opts.MaxCompletions
	for _, c := range completions {
		max = gwutil.Max(max, len(c))
	}

	menu2Widgets := newMenuWidgets(w.ed, completions)
	w.completions = completions
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		w.completionsList.SetWalker(list.NewSimpleListWalker(menu2Widgets), app)
		// whenever there's an update, take focus away from drop down. This means enter
		// can be used to submit a new filter.
		w.completionsActivator.active = false
		w.dropDown.SetWidth(gowid.RenderWithUnits{U: max + 2}, app)
	}))
}

func (w *Widget) Close() error {
	// Two for the aggregator goroutine and the filter runner goroutine
	w.quitchan <- struct{}{}
	w.quitchan <- struct{}{}
	return nil
}

func (w *Widget) OnSubmit(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w, SubmitCB{}, f)
}

func (w *Widget) OnIntermediate(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w, IntermediateCB{}, f)
}

func (w *Widget) OnValid(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w, ValidCB{}, f)
}

func (w *Widget) OnInvalid(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w, InvalidCB{}, f)
}

func (w *Widget) IsValid() bool {
	return w.validitySite.SubWidget() == w.valid
}

func (w *Widget) Value() string {
	return w.ed.Text()
}

func (w *Widget) SetValue(v string, app gowid.IApp) {
	w.ed.SetText(v, app)
	w.ed.SetCursorPos(len(v), app)
}

func (w *Widget) Menus() []gowid.IMenuCompatible {
	return []gowid.IMenuCompatible{w.dropDown}
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return gowid.RenderSize(w.wrapped, size, focus, app)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	// It can be disabled if e.g. the user's last input caused the filter value to
	// be submitted. Then the best UX is to not display the drop down until further input
	// or cursor movement.
	if focus.Focus && len(w.completions) > 0 && !*w.temporarilyDisabled {
		w.dropDown.Open(w.dropDownSite, app)
	} else {
		w.dropDown.Close(app)
	}
	return w.wrapped.Render(size, focus, app)
}

// Reject tab because I want it to switch views. Not intended to be transferable. Reject down because
// accepting it triggers the OnCursorSet callback, which re-evaluates the filter value - the user sees
// it go orange briefly, which is unpleasant.
func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if evk, ok := ev.(*tcell.EventKey); ok {
		if evk.Key() == tcell.KeyTAB || (vim.KeyIn(evk, vim.AllDownKeys) && !termshark.KeyPressIsPrintable(evk)) {
			return false
		}
	}
	*w.temporarilyDisabled = false // any input should start the appearance of the drop down again
	return w.wrapped.UserInput(ev, size, focus, app)
}

//======================================================================

// activatorWidget is intended to wrap a ListBox, and will suppress focus to the listbox by
// default, which has the effect of not highlighting any listbox items. The intended effect
// is for the cursor to be "above" the first item. When the user hits down, then focus
// is passed through, so the top item is highlighted. If the key pressed is up, and the
// listbox doesn't handle it, that must mean it's at the top of its range, so the effect is
// start suppressing focus again.
type activatorWidget struct {
	gowid.IWidget
	active bool
}

func (w *activatorWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if ev, ok := ev.(*tcell.EventKey); ok && !w.active {
		if vim.KeyIn(ev, vim.AllDownKeys) && !termshark.KeyPressIsPrintable(ev) {
			w.active = true
			return true
		} else {
			return false
		}
	}
	res := w.IWidget.UserInput(ev, size, focus, app)
	if !res {
		if ev, ok := ev.(*tcell.EventKey); ok && w.active {
			if vim.KeyIn(ev, vim.AllUpKeys) && !termshark.KeyPressIsPrintable(ev) {
				w.active = false
				return true
			} else {
				return false
			}
		}
	}
	return res
}

func (w *activatorWidget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	newf := focus
	if !w.active {
		newf = gowid.NotSelected
	}
	return w.IWidget.Render(size, newf, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
