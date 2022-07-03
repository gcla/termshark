// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package tableutil contains user-interface functions and helpers for termshark's
// tables - in particular, helpers for vim key sequences like 5gg and G
package tableutil

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

type GoToAdapter struct {
	*table.BoundedWidget
	*termshark.KeyState
}

var _ IGoToLineRequested = (*GoToAdapter)(nil)

func (t *GoToAdapter) GoToLineOrTop(evk *tcell.EventKey) (bool, int) {
	num := -1
	if t.NumberPrefix != -1 {
		num = t.NumberPrefix - 1
	}
	return evk.Key() == tcell.KeyRune && evk.Rune() == 'g' && t.PartialgCmd, num
}

func (t *GoToAdapter) GoToLineOrBottom(evk *tcell.EventKey) (bool, int) {
	num := -1
	if t.NumberPrefix != -1 {
		num = t.NumberPrefix - 1
	}
	return evk.Key() == tcell.KeyRune && evk.Rune() == 'G', num
}

type IGoToLineRequested interface {
	GoToLineOrTop(evk *tcell.EventKey) (bool, int)    // -1 means top
	GoToLineOrBottom(evk *tcell.EventKey) (bool, int) // -1 means bottom
	GoToFirst(gowid.IApp) bool
	GoToLast(gowid.IApp) bool
	GoToNth(gowid.IApp, int) bool
}

// GotoHander retrusn a function suitable for the appkeys widget - it will
// check to see if the key represents a supported action on the table and
// then runs the action if so.
func GotoHandler(t IGoToLineRequested) appkeys.KeyInputFn {
	return func(evk *tcell.EventKey, app gowid.IApp) bool {
		handled := false
		if t != nil {
			handled = true
			if doit, line := t.GoToLineOrTop(evk); doit {
				if line == -1 {
					t.GoToFirst(app)
				} else {
					// psml starts counting at 1
					t.GoToNth(app, line)
				}
			} else if doit, line := t.GoToLineOrBottom(evk); doit {
				if line == -1 {
					t.GoToLast(app)
				} else {
					// psml starts counting at 1
					t.GoToNth(app, line)
				}
			} else {
				handled = false
			}
		}
		return handled
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
