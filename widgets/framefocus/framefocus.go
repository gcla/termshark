// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package framefocus provides a very specific widget to apply a frame around the widget in focus
// and an empty frame if not.
package framefocus

import (
	"runtime"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/isselected"
)

//======================================================================

type Widget struct {
	*isselected.Widget
	h *holder.Widget
}

func New(w gowid.IWidget) *Widget {
	h := holder.New(w)

	noFocusFrame := framed.SpaceFrame
	noFocusFrame.T = 0
	noFocusFrame.B = 0

	return &Widget{
		Widget: isselected.New(
			framed.New(h, framed.Options{
				Frame: noFocusFrame,
			}),
			framed.NewUnicodeAlt2(h),
			framed.NewUnicode(h),
		),
		h: h,
	}
}

func NewSlim(w gowid.IWidget) *Widget {
	h := holder.New(w)

	noFocusFrame := framed.SpaceFrame
	selectedFrame := framed.UnicodeAlt2Frame
	focusFrame := framed.UnicodeFrame
	if runtime.GOOS == "windows" {
		selectedFrame = framed.UnicodeFrame
		focusFrame = framed.UnicodeAlt2Frame
	}
	noFocusFrame.T = 0
	noFocusFrame.B = 0
	selectedFrame.T = 0
	selectedFrame.B = 0
	focusFrame.T = 0
	focusFrame.B = 0

	return &Widget{
		Widget: isselected.New(
			framed.New(h, framed.Options{
				Frame: noFocusFrame,
			}),
			framed.New(h, framed.Options{
				Frame: selectedFrame,
			}),
			framed.New(h, framed.Options{
				Frame: focusFrame,
			}),
		),
		h: h,
	}
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.h.SubWidget()
}

func (w *Widget) SetSubWidget(wi gowid.IWidget, app gowid.IApp) {
	w.h.SetSubWidget(wi, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
