// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package trackfocus provides a widget that issues callbacks when a widget loses or gains the focus.
package trackfocus

import (
	"github.com/gcla/gowid"
)

//======================================================================

type Widget struct {
	gowid.IWidget
	init bool
	last bool
	cb   *gowid.Callbacks
}

func New(w gowid.IWidget) *Widget {
	return &Widget{
		IWidget: w,
		cb:      gowid.NewCallbacks(),
	}
}

// Markers to track the callbacks being added. These just need to be distinct
// from other markers.
type FocusLostCB struct{}
type FocusGainedCB struct{}

// Boilerplate to make the widget provide methods to add and remove callbacks.
func (w *Widget) OnFocusLost(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w.cb, FocusLostCB{}, f)
}

func (w *Widget) RemoveOnFocusLost(f gowid.IIdentity) {
	gowid.RemoveWidgetCallback(w.cb, FocusLostCB{}, f)
}

func (w *Widget) OnFocusGained(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w.cb, FocusGainedCB{}, f)
}

func (w *Widget) RemoveOnFocusGained(f gowid.IIdentity) {
	gowid.RemoveWidgetCallback(w.cb, FocusGainedCB{}, f)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	res := w.IWidget.Render(size, focus, app)
	if w.init && focus.Focus != w.last {
		if focus.Focus {
			gowid.RunWidgetCallbacks(w.cb, FocusGainedCB{}, app, w)
		} else {
			gowid.RunWidgetCallbacks(w.cb, FocusLostCB{}, app, w)
		}
	}
	w.init = true
	w.last = focus.Focus
	return res
}

// Provide IComposite and ISettableComposite. This makes the widget cooperate with general
// utilities that walk the widget hierarchy, like FocusPath().
func (w *Widget) SubWidget() gowid.IWidget {
	return w.IWidget
}

func (w *Widget) SetSubWidget(wi gowid.IWidget, app gowid.IApp) {
	w.IWidget = wi
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
