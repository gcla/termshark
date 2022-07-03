// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package enableselected provides a widget that turns on focus.Selected.
// It can be used to wrap container widgets (pile, columns) which may
// change their look according to the selected state. One use for this is
// highlighting selected rows or columns when the widget itself is not in
// focus.
package enableselected

import (
	"github.com/gcla/gowid"
)

//======================================================================

// Widget turns on the selected field in the Widget when operations are done on this widget. Then
// children widgets that respond to the selected state will be activated.
type Widget struct {
	gowid.IWidget
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.IComposite = (*Widget)(nil)

func New(w gowid.IWidget) *Widget {
	return &Widget{w}
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.IWidget
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	focus.Selected = true
	return gowid.RenderSize(w.IWidget, size, focus, app)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	focus.Selected = true
	return w.IWidget.Render(size, focus, app)
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	focus.Selected = true
	return w.IWidget.UserInput(ev, size, focus, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
