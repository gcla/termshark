// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
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

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
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
	"github.com/gcla/termshark"
	"github.com/gcla/termshark/widgets/appkeys"
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
	wrapped           gowid.IWidget
	opts              Options
	ed                *edit.Widget     // what the user types into - wrapped by validity styling
	dropDown          *menu.Widget     // the menu of possible completions
	dropDownSite      *menu.SiteWidget // where in this widget structure the drop down is rendered
	validitySite      *holder.Widget   // the widget swaps out the contents of this placeholder on validity changes
	valid             gowid.IWidget    // what to display when the filter value is valid
	invalid           gowid.IWidget    // what to display when the filter value is invalid
	intermediate      gowid.IWidget    // what to display when the filter value's validity is being determined
	edCtx             context.Context
	edCancelFn        context.CancelFunc
	fields            termshark.IPrefixCompleter // provides completions, given a prefix
	completionsList   *list.Widget               // the filter widget replaces the list walker when new completions are generated
	completions       []string                   // the current set of completions, used when rendering
	runthisfilterchan chan *filtStruct
	filterchangedchan chan *filtStruct
	quitchan          chan struct{}
	readytorunchan    chan struct{}
	*gowid.Callbacks
	gowid.IsSelectable
}

var _ gowid.IWidget = (*Widget)(nil)
var _ io.Closer = (*Widget)(nil)

type IntermediateCB struct{}
type ValidCB struct{}
type InvalidCB struct{}

type Options struct {
	Completer      termshark.IPrefixCompleter
	MaxCompletions int
}

func New(opt Options) *Widget {
	ed := edit.New()

	fixed := gowid.RenderFixed{}
	l2 := list.New(list.NewSimpleListWalker([]gowid.IWidget{}))

	if opt.MaxCompletions == 0 {
		opt.MaxCompletions = 20
	}

	menuListBox2 := styled.New(
		framed.NewUnicode(cellmod.Opaque(l2)),
		gowid.MakePaletteRef("filter-menu-focus"),
	)

	drop := menu.New("filter", menuListBox2, gowid.RenderWithUnits{U: opt.MaxCompletions + 2},
		menu.Options{
			IgnoreKeysProvided: true,
			IgnoreKeys: []gowid.IKey{
				gowid.MakeKeyExt(tcell.KeyUp),
				gowid.MakeKeyExt(tcell.KeyDown),
			},
			CloseKeysProvided: true,
			CloseKeys:         []gowid.IKey{},
		},
	)

	site := menu.NewSite(menu.SiteOptions{
		YOffset: 1,
	})

	onelineEd := appkeys.New(ed, filterOutEnter, appkeys.Options{
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

	res := &Widget{
		wrapped:           wrapped,
		opts:              opt,
		ed:                ed,
		dropDown:          drop,
		dropDownSite:      site,
		validitySite:      placeholder,
		valid:             valid,
		invalid:           invalid,
		intermediate:      intermediate,
		fields:            opt.Completer,
		completionsList:   l2,
		completions:       []string{},
		filterchangedchan: filterchangedchan,
		runthisfilterchan: runthisfilterchan,
		quitchan:          quitchan,
		readytorunchan:    readytorunchan,
		Callbacks:         gowid.NewCallbacks(),
	}

	validcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.valid, app)
				gowid.RunWidgetCallbacks(res.Callbacks, ValidCB{}, app, res)
			}))
		},
	}

	invalidcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.invalid, app)
				gowid.RunWidgetCallbacks(res.Callbacks, InvalidCB{}, app, res)
			}))
		},
	}

	killedcb := &ValidateCB{
		Fn: func(app gowid.IApp) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				res.validitySite.SetSubWidget(res.intermediate, app)
				gowid.RunWidgetCallbacks(res.Callbacks, IntermediateCB{}, app, res)
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
			res.readytorunchan <- struct{}{}
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

	ed.OnTextSet(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, ew gowid.IWidget) {
		// Shortcut - we know that "" is always valid
		if ed.Text() != "" {
			res.validitySite.SetSubWidget(res.intermediate, app)
			gowid.RunWidgetCallbacks(res.Callbacks, IntermediateCB{}, app, res)
		}

		if res.edCancelFn != nil {
			res.edCancelFn()
		}
		res.edCtx, res.edCancelFn = context.WithCancel(context.Background())

		// don't kick things off right away in case user is typing fast
		go func(ctx context.Context) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond * 200):
				break
			}

			res.filterchangedchan <- &filtStruct{ed.Text(), app}

			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				_, y := app.GetScreen().Size()
				makeCompletions(res.fields, ed.Text(), y, app, func(completions []string, app gowid.IApp) {
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						res.processCompletions(completions, app)
					}))
				})
			}))
		}(res.edCtx)
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

func filterOutEnter(evk *tcell.EventKey, app gowid.IApp) bool {
	handled := false
	switch evk.Key() {
	case tcell.KeyEnter:
		handled = true
	}
	return handled
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
				SelectKeys:         []gowid.IKey{gowid.MakeKeyExt(tcell.KeyEnter)},
			},
		)
		clickmeStyled := styled.NewInvertedFocus(clickme, gowid.MakePaletteRef("filter-menu-focus"))
		clickme.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
			txt := ed.Text()
			end := ed.CursorPos()
			start := end
			for {
				if start == 0 {
					break
				}
				if start < len(txt) && txt[start] == ' ' {
					start++
					break
				}
				start--
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

func (w *Widget) UpdateCompletions(app gowid.IApp) {
	makeCompletions(w.fields, "", w.opts.MaxCompletions, app, func(completions []string, app gowid.IApp) {
		w.processCompletions(completions, app)
	})
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
		w.dropDown.SetWidth(gowid.RenderWithUnits{U: max + 2}, app)
	}))
}

func (w *Widget) Close() error {
	// Two for the aggregator goroutine and the filter runner goroutine
	w.quitchan <- struct{}{}
	w.quitchan <- struct{}{}
	return nil
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
}

func (w *Widget) Menus() []gowid.IMenuCompatible {
	return []gowid.IMenuCompatible{w.dropDown}
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return gowid.RenderSize(w.wrapped, size, focus, app)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if focus.Focus && len(w.completions) > 0 {
		w.dropDown.Open(w.dropDownSite, app)
	} else {
		w.dropDown.Close(app)
	}
	return w.wrapped.Render(size, focus, app)
}

// Reject tab because I want it to switch views. Not intended to be transferable.
func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if evk, ok := ev.(*tcell.EventKey); ok && evk.Key() == tcell.KeyTAB {
		return false
	}
	return gowid.UserInput(w.wrapped, ev, size, focus, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
