// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package mapkeys provides a widget that can map one keypress to a sequence of
// keypresses. If the user pnovides as input a key that is mapped, the sequence of
// resulting keypresses is played to the subwidget before control returns. If the key is
// not mapped, it is passed through as normal. I'm going to use this to provide a vim-like
// macro feature in termshark.
package mapkeys

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/vim"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

type Widget struct {
	gowid.IWidget
	kmap map[vim.KeyPress]vim.KeySequence
}

var _ gowid.IWidget = (*Widget)(nil)

func New(w gowid.IWidget) *Widget {
	res := &Widget{
		IWidget: w,
		kmap:    make(map[vim.KeyPress]vim.KeySequence),
	}
	return res
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	switch ev := ev.(type) {
	case *tcell.EventKey:
		kp := vim.KeyPressFromTcell(ev)
		if seq, ok := w.kmap[kp]; ok {
			var res bool
			for _, vk := range seq {
				k := gowid.Key(vk)
				// What should the handled value be??
				res = w.IWidget.UserInput(tcell.NewEventKey(k.Key(), k.Rune(), k.Modifiers()), size, focus, app)
			}
			return res
		} else {
			return w.IWidget.UserInput(ev, size, focus, app)
		}
	default:
		return w.IWidget.UserInput(ev, size, focus, app)
	}
}

func (w *Widget) AddMapping(from vim.KeyPress, to vim.KeySequence, app gowid.IApp) {
	w.kmap[from] = to
}

func (w *Widget) RemoveMapping(from vim.KeyPress, app gowid.IApp) {
	delete(w.kmap, from)
}

// ClearMappings will remove all mappings. I deliberately preserve the same dictionary,
// though in case I decide in the future it's useful to let clients have direct access to
// the map (and so maybe store it somewhere).
func (w *Widget) ClearMappings(app gowid.IApp) {
	for k := range w.kmap {
		delete(w.kmap, k)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 90
// End:
