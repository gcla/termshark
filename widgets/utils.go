// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package widgets

import (
	"github.com/gcla/gowid"
	"github.com/gdamore/tcell"
)

//======================================================================

func SwallowMouseScroll(ev *tcell.EventMouse, app gowid.IApp) bool {
	res := false
	switch ev.Buttons() {
	case tcell.WheelDown:
		res = true
	case tcell.WheelUp:
		res = true
	}
	return res
}

func SwallowMovementKeys(ev *tcell.EventKey, app gowid.IApp) bool {
	res := false
	switch ev.Key() {
	case tcell.KeyDown, tcell.KeyCtrlN, tcell.KeyUp, tcell.KeyCtrlP, tcell.KeyRight, tcell.KeyCtrlF, tcell.KeyLeft, tcell.KeyCtrlB:
		res = true
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'h', 'j', 'k', 'l':
			res = true
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
