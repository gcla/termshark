// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package keepselected turns on the selected bit when Render or UserInput is called.
package keepselected

import "github.com/gcla/gowid"

// A widget to ensure that its subwidget is always rendered as "selected", even if it's
// not in focus. This allows a composite widget to style its selected child even without
// focus so the user can see which child is active.
type Widget struct {
	sub gowid.IWidget
}

func New(w gowid.IWidget) *Widget {
	return &Widget{
		sub: w,
	}
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	return w.sub.Render(size, focus.SelectIf(true), app)
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return w.sub.RenderSize(size, focus.SelectIf(true), app)
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return w.sub.UserInput(ev, size, focus.SelectIf(true), app)
}

func (w *Widget) Selectable() bool {
	return w.sub.Selectable()
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.sub
}

func (w *Widget) SetSubWidget(wi gowid.IWidget, app gowid.IApp) {
	w.sub = wi
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
