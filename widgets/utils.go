// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package widgets

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gdamore/tcell/v2"
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

// Return false if it was already open
type MenuOpenerFunc func(bool, *menu.Widget, menu.ISite, gowid.IApp) bool

func (m MenuOpenerFunc) OpenMenu(mu *menu.Widget, site *menu.SiteWidget, app gowid.IApp) bool {
	return m(true, mu, site, app)
}

func (m MenuOpenerFunc) CloseMenu(mu *menu.Widget, app gowid.IApp) {
	m(false, mu, nil, app)
}

func OpenSimpleMenu(open bool, mu *menu.Widget, site menu.ISite, app gowid.IApp) bool {
	if open {
		mu.Open(site, app)
		return true
	} else {
		mu.Close(app)
		return true
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
