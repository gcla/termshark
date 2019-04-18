// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package withscrollbar provides a widget that renders with a scrollbar on the right
package withscrollbar

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/vscroll"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type Widget struct {
	*columns.Widget
	w        IScrollSubWidget
	sb       *vscroll.Widget
	goUpDown int // positive means down
	pgUpDown int // positive means down
}

type IScrollSubWidget interface {
	gowid.IWidget
	CalculateOnScreen(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) (int, int, int, error)
	Up(lines int, size gowid.IRenderSize, app gowid.IApp)
	Down(lines int, size gowid.IRenderSize, app gowid.IApp)
	UpPage(num int, size gowid.IRenderSize, app gowid.IApp)
	DownPage(num int, size gowid.IRenderSize, app gowid.IApp)
}

func New(w IScrollSubWidget) *Widget {
	sb := vscroll.NewExt(vscroll.VerticalScrollbarUnicodeRunes)
	res := &Widget{
		Widget: columns.New([]gowid.IContainerWidget{
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
		w:        w,
		sb:       sb,
		goUpDown: 0,
		pgUpDown: 0,
	}
	sb.OnClickAbove(gowid.MakeWidgetCallback("cb", res.clickUp))
	sb.OnClickBelow(gowid.MakeWidgetCallback("cb", res.clickDown))
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

func (e *Widget) clickUpArrow(app gowid.IApp, w gowid.IWidget) {
	e.goUpDown -= 1
}

func (e *Widget) clickDownArrow(app gowid.IApp, w gowid.IWidget) {
	e.goUpDown += 1
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	box, ok := size.(gowid.IRenderBox)
	if !ok {
		panic(gowid.WidgetSizeError{Widget: w, Size: size, Required: "gowid.IRenderBox"})
	}

	ecols := box.BoxColumns() - 1
	ebox := gowid.MakeRenderBox(ecols, box.BoxRows())

	x, y, z, err := w.w.CalculateOnScreen(ebox, focus, app)
	if err != nil {
		log.Error(err)
	}

	w.sb.Top = x
	w.sb.Middle = y
	w.sb.Bottom = z

	res := w.Widget.UserInput(ev, size, focus, app)
	if res {
		w.Widget.SetFocus(app, 0)
	}
	return res
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	box, ok := size.(gowid.IRenderBox)
	if !ok {
		panic(gowid.WidgetSizeError{Widget: w, Size: size, Required: "gowid.IRenderBox"})
	}
	ecols := box.BoxColumns() - 1
	var x int
	var y int
	var z int
	var err error
	if ecols >= 1 {
		ebox := gowid.MakeRenderBox(ecols, box.BoxRows())
		if w.goUpDown != 0 || w.pgUpDown != 0 {
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
		}
		w.goUpDown = 0
		w.pgUpDown = 0

		x, y, z, err = w.w.CalculateOnScreen(ebox, focus, app)
		if err != nil {
			log.Error(err)
		}
	}
	w.sb.Top = x
	w.sb.Middle = y
	w.sb.Bottom = z

	canvas := gowid.Render(w.Widget, size, focus, app)

	return canvas
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
