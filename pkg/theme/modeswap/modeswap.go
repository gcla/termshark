// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	modeHi  gowid.IColor
	mode256 gowid.IColor
	mode16  gowid.IColor
}

var _ gowid.IColor = (*Color)(nil)

func New(hi, mid, lo gowid.IColor) *Color {
	return &Color{
		modeHi:  hi,
		mode256: mid,
		mode16:  lo,
	}
}

func (c *Color) ToTCellColor(mode gowid.ColorMode) (gowid.TCellColor, bool) {
	var col gowid.IColor = c.mode16
	switch mode {
	case gowid.Mode24BitColors:
		col = c.modeHi
	case gowid.Mode256Colors:
		col = c.mode256
	default:
		col = c.mode16
	}
	return col.ToTCellColor(mode)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
