// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package expander provides a widget that renders in one line when not in focus
// but that may render using more than one line when in focus. This is useful for
// showing an item in full when needed, but otherwise saving screen real-estate.
package expander

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/boxadapter"
)

//======================================================================

// Widget will render in one row when not selected, and then using
// however many rows required when selected.
type Widget struct {
	orig gowid.IWidget
	w    *boxadapter.Widget
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.IComposite = (*Widget)(nil)

func New(w gowid.IWidget) *Widget {
	b := boxadapter.New(w, 1)
	return &Widget{w, b}
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.orig
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	if focus.Selected {
		return gowid.RenderSize(w.orig, size, focus, app)
	} else {
		return gowid.RenderSize(w.w, size, focus, app)
	}
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if focus.Selected {
		return w.orig.Render(size, focus, app)
	} else {
		return w.w.Render(size, focus, app)
	}
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if focus.Selected {
		return w.orig.UserInput(ev, size, focus, app)
	} else {
		return w.w.UserInput(ev, size, focus, app)
	}
}

func (w *Widget) Selectable() bool {
	return w.w.Selectable()
}

func (w *Widget) String() string {
	return fmt.Sprintf("expander[%v]", w.w.IWidget)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
