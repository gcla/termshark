// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package scrollabletext provides a text widget that can be placed inside
// withscrollbar.Widget
package scrollabletext

import (
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

// Widget constructs a text widget and allows it to be scrolled. But this widget is limited - it assumes no
// line will wrap. To make this happen it ensures that any lines that are too long are clipped. It makes this
// assumption because my scrollbar APIs are not well designed, and functions like ScrollPosition and
// ScrollLength don't understand the current rendering context. That means if the app is resized, and a line
// now takes two screen lines to render and not one, the scrollbar can't be built accurately. Until I design
// a better scrollbar API, this will work - I'm only using it for limited information dialogs at the moment.
type Widget struct {
	*selectable.Widget
	splitText    []string
	linesFromTop int // how many lines down we are
	cachedLength int
}

var _ gowid.IWidget = (*Widget)(nil)

func New(txt string) *Widget {
	splitText := strings.Split(txt, "\n")
	res := &Widget{
		splitText:    splitText,
		cachedLength: len(splitText),
	}
	res.makeText()
	return res
}

func (w *Widget) makeText() {
	w.Widget = selectable.New(
		text.New(
			strings.Join(w.splitText[w.linesFromTop:], "\n"),
			text.Options{
				Wrap:          text.WrapClip,
				ClipIndicator: "...",
			},
		),
	)
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	handled := true
	linesFromTop := w.linesFromTop
	switch ev := ev.(type) {
	case *tcell.EventKey:
		switch ev.Key() {
		case tcell.KeyPgUp:
			w.UpPage(1, size, app)
		case tcell.KeyUp, tcell.KeyCtrlP:
			w.Up(1, size, app)
		case tcell.KeyDown, tcell.KeyCtrlN:
			w.Down(1, size, app)
		case tcell.KeyPgDn:
			w.DownPage(1, size, app)
		default:
			handled = false
		}
	}

	if handled && linesFromTop == w.linesFromTop {
		handled = false
	}

	if !handled {
		handled = w.Widget.UserInput(ev, size, focus, app)
	}

	return handled
}

// Implement functions for withscrollbar.Widget
func (w *Widget) ScrollPosition() int {
	return w.linesFromTop
}

func (w *Widget) ScrollLength() int {
	return w.cachedLength
}

func (w *Widget) Up(lines int, size gowid.IRenderSize, app gowid.IApp) {
	pos := w.linesFromTop
	w.linesFromTop = gwutil.Max(0, w.linesFromTop-lines)
	if pos != w.linesFromTop {
		w.makeText()
	}
}

func (w *Widget) Down(lines int, size gowid.IRenderSize, app gowid.IApp) {
	pos := w.linesFromTop
	w.linesFromTop = gwutil.Min(w.cachedLength-1, w.linesFromTop+lines)
	if pos != w.linesFromTop {
		w.makeText()
	}
}

func (w *Widget) UpPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	pos := w.linesFromTop
	pg := 1
	if size, ok := size.(gowid.IRows); ok {
		pg = size.Rows()
	}
	w.linesFromTop = gwutil.Max(0, w.linesFromTop-(pg*num))
	if pos != w.linesFromTop {
		w.makeText()
	}
}

func (w *Widget) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {
	pos := w.linesFromTop
	pg := 1
	if size, ok := size.(gowid.IRows); ok {
		pg = size.Rows()
	}
	w.linesFromTop = gwutil.Min(w.cachedLength-1, w.linesFromTop+(pg*num))
	if pos != w.linesFromTop {
		w.makeText()
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
