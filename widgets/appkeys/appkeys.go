// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package appkeys provides a widget which responds to keyboard input.
package appkeys

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

type IWidget interface {
	gowid.ICompositeWidget
}

type IAppInput interface {
	gowid.IComposite
	ApplyBefore() bool
}

type IAppKeys interface {
	KeyInput(ev *tcell.EventKey, app gowid.IApp) bool
}

type IAppMouse interface {
	MouseInput(ev *tcell.EventMouse, app gowid.IApp) bool
}

type KeyInputFn func(ev *tcell.EventKey, app gowid.IApp) bool
type MouseInputFn func(ev *tcell.EventMouse, app gowid.IApp) bool

type Options struct {
	ApplyBefore bool
}

type Widget struct {
	gowid.IWidget
	opt Options
}

type KeyWidget struct {
	*Widget
	fn KeyInputFn
}

type MouseWidget struct {
	*Widget
	fn MouseInputFn
}

func New(inner gowid.IWidget, fn KeyInputFn, opts ...Options) *KeyWidget {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &KeyWidget{
		Widget: &Widget{
			IWidget: inner,
			opt:     opt,
		},
		fn: fn,
	}

	return res
}

var _ gowid.ICompositeWidget = (*KeyWidget)(nil)
var _ IWidget = (*KeyWidget)(nil)
var _ IAppKeys = (*KeyWidget)(nil)

func NewMouse(inner gowid.IWidget, fn MouseInputFn, opts ...Options) *MouseWidget {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &MouseWidget{
		Widget: &Widget{
			IWidget: inner,
			opt:     opt,
		},
		fn: fn,
	}

	return res
}

var _ gowid.ICompositeWidget = (*MouseWidget)(nil)
var _ IWidget = (*MouseWidget)(nil)
var _ IAppMouse = (*MouseWidget)(nil)

func (w *Widget) String() string {
	return fmt.Sprintf("appkeys[%v]", w.SubWidget())
}

func (w *Widget) ApplyBefore() bool {
	return w.opt.ApplyBefore
}

func (w *KeyWidget) KeyInput(k *tcell.EventKey, app gowid.IApp) bool {
	return w.fn(k, app)
}

func (w *MouseWidget) MouseInput(k *tcell.EventMouse, app gowid.IApp) bool {
	return w.fn(k, app)
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.IWidget
}

func (w *Widget) SetSubWidget(wi gowid.IWidget, app gowid.IApp) {
	w.IWidget = wi
}

func (w *Widget) SubWidgetSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderSize {
	return SubWidgetSize(w, size, focus, app)
}

func (w *KeyWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return UserInput(w, ev, size, focus, app)
}

func (w *MouseWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return UserInput(w, ev, size, focus, app)
}

//======================================================================

func SubWidgetSize(w gowid.ICompositeWidget, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderSize {
	return size
}

func RenderSize(w IWidget, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return gowid.RenderSize(w.SubWidget(), size, focus, app)
}

func UserInput(w IAppInput, ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	var res bool

	if w.ApplyBefore() {
		switch ev := ev.(type) {
		case *tcell.EventKey:
			if wk, ok := w.(IAppKeys); ok {
				res = wk.KeyInput(ev, app)
			}
		case *tcell.EventMouse:
			if wm, ok := w.(IAppMouse); ok {
				res = wm.MouseInput(ev, app)
			}
		}
		if !res {
			res = w.SubWidget().UserInput(ev, size, focus, app)
		}
	} else {
		res = w.SubWidget().UserInput(ev, size, focus, app)
		if !res {
			switch ev := ev.(type) {
			case *tcell.EventKey:
				if wk, ok := w.(IAppKeys); ok {
					res = wk.KeyInput(ev, app)
				}
			case *tcell.EventMouse:
				if wm, ok := w.(IAppMouse); ok {
					res = wm.MouseInput(ev, app)
				}
			}
		}
	}
	return res
}

func Render(w IWidget, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	return w.SubWidget().Render(size, focus, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
