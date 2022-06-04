// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ifwidget provides a simple widget that behaves differently depending on the condition
// supplied.
package ifwidget

import (
	"fmt"

	"github.com/gcla/gowid"
)

//======================================================================

type Widget struct {
	wtrue  gowid.IWidget
	wfalse gowid.IWidget
	pred   Predicate
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.ICompositeWidget = (*Widget)(nil)

type Predicate func() bool

func New(wtrue gowid.IWidget, wfalse gowid.IWidget, pred Predicate) *Widget {
	res := &Widget{
		wtrue:  wtrue,
		wfalse: wfalse,
		pred:   pred,
	}
	return res
}

func (w *Widget) String() string {
	return fmt.Sprintf("ifwidget[%v]", w.SubWidget())
}

func (w *Widget) SubWidget() gowid.IWidget {
	if w.pred() {
		return w.wtrue
	} else {
		return w.wfalse
	}
}

func (w *Widget) SetSubWidget(wi gowid.IWidget, app gowid.IApp) {
	if w.pred() {
		w.wtrue = wi
	} else {
		w.wfalse = wi
	}
}

func (w *Widget) SubWidgetSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderSize {
	return size
}

func (w *Widget) Selectable() bool {
	if w.pred() {
		return w.wtrue.Selectable()
	} else {
		return w.wfalse.Selectable()
	}
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if w.pred() {
		return w.wtrue.UserInput(ev, size, focus, app)
	} else {
		return w.wfalse.UserInput(ev, size, focus, app)
	}
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	if w.pred() {
		return gowid.RenderSize(w.wtrue, size, focus, app)
	} else {
		return gowid.RenderSize(w.wfalse, size, focus, app)
	}
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if w.pred() {
		return w.wtrue.Render(size, focus, app)
	} else {
		return w.wfalse.Render(size, focus, app)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
