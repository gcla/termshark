// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// package modeswap provides an IColor-conforming type Color that renders differently
// if in low-color mode
package modeswap

import (
	"github.com/gcla/gowid"
)

//======================================================================

type Color struct {
	modeReg gowid.IColor
	modeLow gowid.IColor
}

var _ gowid.IColor = (*Color)(nil)

func New(reg, lofi gowid.IColor) *Color {
	return &Color{
		modeReg: reg,
		modeLow: lofi,
	}
}

func (c *Color) ToTCellColor(mode gowid.ColorMode) (gowid.TCellColor, bool) {
	var col gowid.IColor = c.modeLow
	switch mode {
	case gowid.Mode256Colors, gowid.Mode24BitColors:
		col = c.modeReg
	}
	return col.ToTCellColor(mode)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
