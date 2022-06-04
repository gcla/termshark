// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package renderfocused will render a widget with focus true
package renderfocused

import (
	"github.com/gcla/gowid"
)

//======================================================================

type Widget struct {
	gowid.IWidget
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.ICompositeWidget = (*Widget)(nil)

func New(w gowid.IWidget) *Widget {
	return &Widget{
		IWidget: w,
	}
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.IWidget
}

func (w *Widget) SubWidgetSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderSize {
	return w.SubWidget().RenderSize(size, focus, app)
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return gowid.RenderSize(w.IWidget, size, gowid.Focused, app)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	return w.IWidget.Render(size, gowid.Focused, app)
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return w.IWidget.UserInput(ev, size, focus, app)
}

// TODO - this isn't right. Should Selectable be conditioned on focus?
func (w *Widget) Selectable() bool {
	return w.IWidget.Selectable()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
