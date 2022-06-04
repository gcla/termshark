// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import "github.com/gcla/gowid"

//======================================================================

type PaletteSwitcher struct {
	P1        gowid.IPalette
	P2        gowid.IPalette
	ChooseOne *bool
}

var _ gowid.IPalette = (*PaletteSwitcher)(nil)

func (p PaletteSwitcher) CellStyler(name string) (gowid.ICellStyler, bool) {
	if *p.ChooseOne {
		return p.P1.CellStyler(name)
	} else {
		return p.P2.CellStyler(name)
	}
}

func (p PaletteSwitcher) RangeOverPalette(f func(key string, value gowid.ICellStyler) bool) {
	if *p.ChooseOne {
		p.P1.RangeOverPalette(f)
	} else {
		p.P2.RangeOverPalette(f)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
