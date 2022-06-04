// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package withscrollbar provides a widget that renders with a scrollbar on the right
package withscrollbar

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/vscroll"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

type Widget struct {
	always   *columns.Widget // use if scrollbar is to be shown
	w        IScrollSubWidget
	sb       *vscroll.Widget
	goUpDown int     // positive means down
	pgUpDown int     // positive means down
	frac     float32 // positive means down
	fracSet  bool
	opt      Options
}

var _ gowid.IWidget = (*Widget)(nil)

type Options struct {
	HideIfContentFits bool
}

type IScrollValues interface {
	ScrollPosition() int
	ScrollLength() int
}

// Implemented by widgets that can scroll
type IScrollOneLine interface {
	Up(lines int, size gowid.IRenderSize, app gowid.IApp)
	Down(lines int, size gowid.IRenderSize, app gowid.IApp)
}

type IScrollOnePage interface {
	UpPage(num int, size gowid.IRenderSize, app gowid.IApp)
	DownPage(num int, size gowid.IRenderSize, app gowid.IApp)
}

type IScrollHome interface {
	GoHome(size gowid.IRenderSize, app gowid.IApp)
}

type IScrollToEnd interface {
	GoToEnd(size gowid.IRenderSize, app gowid.IApp)
}

type IScrollSubWidget interface {
	gowid.IWidget
	IScrollValues
	IScrollOneLine
	IScrollOnePage
}

func New(w IScrollSubWidget, opts ...Options) *Widget {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	sb := vscroll.NewExt(vscroll.VerticalScrollbarUnicodeRunes)
	res := &Widget{
		always: columns.New([]gowid.IContainerWidget{
			&gowid.ContainerWidget{
				IWidget: w,
				D:       gowid.RenderWithWeight{W: 1},
			},
			// So that the vscroll doesn't take the focus when moving from above
			// and below in the main termshark window
			&gowid.ContainerWidget{
				IWidget: selectable.NewUnselectable(sb),
				D:       gowid.RenderWithUnits{U: 1},
			},
		}),
		w:   w,
		sb:  sb,
		opt: opt,
	}
	sb.OnClickAbove(gowid.MakeWidgetCallback("cb", res.clickUp))
	sb.OnClickBelow(gowid.MakeWidgetCallback("cb", res.clickDown))
	sb.OnRightClick(gowid.MakeWidgetCallbackExt("cb", res.rightClick))
	sb.OnClickUpArrow(gowid.MakeWidgetCallback("cb", res.clickUpArrow))
	sb.OnClickDownArrow(gowid.MakeWidgetCallback("cb", res.clickDownArrow))
	return res
}

func (e *Widget) clickUp(app gowid.IApp, w gowid.IWidget) {
	e.pgUpDown -= 1
}

func (e *Widget) clickDown(app gowid.IApp, w gowid.IWidget) {
	e.pgUpDown += 1
}

func (e *Widget) rightClick(app gowid.IApp, w gowid.IWidget, data ...interface{}) {
	frac := data[0].(float32)
	e.frac = frac
	e.fracSet = true
}

func (e *Widget) clickUpArrow(app gowid.IApp, w gowid.IWidget) {
	e.goUpDown -= 1
}

func (e *Widget) clickDownArrow(app gowid.IApp, w gowid.IWidget) {
	e.goUpDown += 1
}

// Don't attempt to calculate actual rendered rows - it's terribly slow, and O(n) rows.
func CalculateMenuRows(vals IScrollValues, rows int, focus gowid.Selector, app gowid.IApp) (int, int, int) {
	return vals.ScrollPosition(), 1, vals.ScrollLength() - (vals.ScrollPosition() + 1)
}

func (w *Widget) contentFits(size gowid.IRenderSize) bool {
	res := true
	if rower, ok := size.(gowid.IRows); ok {
		res = (w.w.ScrollLength() <= rower.Rows())
	}
	return res
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	if w.opt.HideIfContentFits && w.contentFits(size) {
		return w.w.UserInput(ev, size, focus, app)
	}

	box, ok := size.(gowid.IRenderBox)
	if !ok {
		panic(gowid.WidgetSizeError{Widget: w, Size: size, Required: "gowid.IRenderBox"})
	}

	x, y, z := CalculateMenuRows(w.w, box.BoxRows(), focus, app)

	w.sb.Top = x
	w.sb.Middle = y
	w.sb.Bottom = z

	if ws, ok := w.w.(IScrollOnePage); ok {
		if ev, ok := ev.(*tcell.EventKey); ok {
			switch ev.Key() {
			case tcell.KeyPgUp:
				ws.UpPage(1, size, app)
				return true
			case tcell.KeyPgDn:
				ws.DownPage(1, size, app)
				return true
			}
		}
	}

	if ws, ok := w.w.(IScrollHome); ok {
		if ev, ok := ev.(*tcell.EventKey); ok {
			switch ev.Key() {
			case tcell.KeyHome:
				ws.GoHome(size, app)
				return true
			}
		}
	}

	if ws, ok := w.w.(IScrollToEnd); ok {
		if ev, ok := ev.(*tcell.EventKey); ok {
			switch ev.Key() {
			case tcell.KeyEnd:
				ws.GoToEnd(size, app)
				return true
			}
		}
	}

	res := w.always.UserInput(ev, size, focus, app)
	if res {
		w.always.SetFocus(app, 0)
	}
	return res
}

type iSetPosition interface {
	SetPos(pos list.IBoundedWalkerPosition, app gowid.IApp)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if w.opt.HideIfContentFits && w.contentFits(size) {
		return w.w.Render(size, focus, app)
	}

	var box gowid.IRenderBox
	var ok bool
	box, ok = size.(gowid.IRenderBox)
	if !ok {
		box = w.always.Render(size, focus, app)
	}
	ecols := box.BoxColumns() - 1
	var x int
	var y int
	var z int
	if ecols >= 1 {
		ebox := gowid.MakeRenderBox(ecols, box.BoxRows())
		if w.goUpDown != 0 || w.pgUpDown != 0 || w.fracSet {
			if w.goUpDown > 0 {
				w.w.Down(w.goUpDown, ebox, app)
			} else if w.goUpDown < 0 {
				w.w.Up(-w.goUpDown, ebox, app)
			}

			if w.pgUpDown > 0 {
				w.w.DownPage(w.pgUpDown, ebox, app)
			} else if w.pgUpDown < 0 {
				w.w.UpPage(-w.pgUpDown, ebox, app)
			}

			if w.fracSet {
				if wp, ok := w.w.(iSetPosition); ok {
					wp.SetPos(table.Position(int(float32(w.w.ScrollLength()-1)*w.frac)), app)
				}
				w.fracSet = false
			}
		}
		w.goUpDown = 0
		w.pgUpDown = 0

		x, y, z = CalculateMenuRows(w.w, box.BoxRows(), focus, app)
	}
	w.sb.Top = x
	w.sb.Middle = y
	w.sb.Bottom = z

	canvas := w.always.Render(size, focus, app)

	return canvas
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	if w.opt.HideIfContentFits && w.contentFits(size) {
		return w.w.RenderSize(size, focus, app)
	}

	return w.always.RenderSize(size, focus, app)
}

func (w *Widget) Selectable() bool {
	return w.w.Selectable()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
