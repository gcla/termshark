// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/modeswap"
)

//======================================================================

var (
	LightGray   gowid.GrayColor = gowid.MakeGrayColor("g74")
	MediumGray  gowid.GrayColor = gowid.MakeGrayColor("g50")
	DarkGray    gowid.GrayColor = gowid.MakeGrayColor("g35")
	BrightBlue  gowid.RGBColor  = gowid.MakeRGBColor("#08f")
	BrightGreen gowid.RGBColor  = gowid.MakeRGBColor("#6f2")
	LightRed    gowid.RGBColor  = gowid.MakeRGBColor("#ebb")
	LightBlue   gowid.RGBColor  = gowid.MakeRGBColor("#abf")
	DarkRed     gowid.RGBColor  = gowid.MakeRGBColor("#311")
	DarkBlue    gowid.RGBColor  = gowid.MakeRGBColor("#01f")

	//======================================================================
	// Regular mode
	//

	//                                                      256 color   < 256 color
	PktListRowSelectedBgReg  *modeswap.Color = modeswap.New(MediumGray, gowid.ColorBlack)
	PktListRowFocusBgReg     *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	PktListCellSelectedFgReg *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	PktListCellSelectedBgReg *modeswap.Color = modeswap.New(DarkGray, gowid.ColorBlack)
	PktStructSelectedBgReg   *modeswap.Color = modeswap.New(MediumGray, gowid.ColorBlack)
	PktStructFocusBgReg      *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	HexTopUnselectedFgReg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	HexTopUnselectedBgReg    *modeswap.Color = modeswap.New(MediumGray, gowid.ColorBlack)
	HexTopSelectedFgReg      *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	HexTopSelectedBgReg      *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	HexBottomUnselectedFgReg *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexBottomUnselectedBgReg *modeswap.Color = modeswap.New(LightGray, gowid.ColorBlack)
	HexBottomSelectedFgReg   *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexBottomSelectedBgReg   *modeswap.Color = modeswap.New(LightGray, gowid.ColorBlack)
	HexCurUnselectedFgReg    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	HexCurUnselectedBgReg    *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexLineFgReg             *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexLineBgReg             *modeswap.Color = modeswap.New(LightGray, gowid.ColorBlack)
	FilterValidBgReg         *modeswap.Color = modeswap.New(BrightGreen, gowid.ColorGreen)
	StreamClientFg           *modeswap.Color = modeswap.New(DarkRed, gowid.ColorWhite)
	StreamClientBg           *modeswap.Color = modeswap.New(LightRed, gowid.ColorDarkRed)
	StreamServerFg           *modeswap.Color = modeswap.New(DarkBlue, gowid.ColorWhite)
	StreamServerBg           *modeswap.Color = modeswap.New(LightBlue, gowid.ColorBlue)

	RegularPalette gowid.Palette = gowid.Palette{
		"default":                gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorWhite),
		"title":                  gowid.MakeForeground(gowid.ColorDarkRed),
		"pkt-list-row-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, PktListRowFocusBgReg),
		"pkt-list-cell-focus":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorPurple),
		"pkt-list-row-selected":  gowid.MakePaletteEntry(gowid.ColorWhite, PktListRowSelectedBgReg),
		"pkt-list-cell-selected": gowid.MakePaletteEntry(PktListCellSelectedFgReg, PktListCellSelectedBgReg),
		"pkt-struct-focus":       gowid.MakePaletteEntry(gowid.ColorWhite, PktStructFocusBgReg),
		"pkt-struct-selected":    gowid.MakePaletteEntry(gowid.ColorWhite, PktStructSelectedBgReg),
		"filter-menu-focus":      gowid.MakeStyledPaletteEntry(gowid.ColorBlack, gowid.ColorWhite, gowid.StyleBold),
		"filter-valid":           gowid.MakePaletteEntry(gowid.ColorBlack, FilterValidBgReg),
		"filter-invalid":         gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorRed),
		"filter-intermediate":    gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorOrange),
		"dialog":                 gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"dialog-buttons":         gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"button":                 gowid.MakePaletteEntry(gowid.ColorDarkBlue, ButtonBg),
		"button-focus":           gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkBlue),
		"progress-default":       gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"progress-complete":      gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(gowid.ColorMagenta)),
		"progress-spinner":       gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"hex-cur-selected":       gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"hex-cur-unselected":     gowid.MakePaletteEntry(HexCurUnselectedFgReg, HexCurUnselectedBgReg),
		"hex-top-selected":       gowid.MakePaletteEntry(HexTopSelectedFgReg, HexTopSelectedBgReg),
		"hex-top-unselected":     gowid.MakePaletteEntry(HexTopUnselectedFgReg, HexTopUnselectedBgReg),
		"hex-bottom-selected":    gowid.MakePaletteEntry(HexBottomSelectedFgReg, HexBottomSelectedBgReg),
		"hex-bottom-unselected":  gowid.MakePaletteEntry(HexBottomUnselectedFgReg, HexBottomUnselectedBgReg),
		"hexln-selected":         gowid.MakePaletteEntry(HexLineFgReg, HexLineBgReg),
		"hexln-unselected":       gowid.MakePaletteEntry(HexLineFgReg, HexLineBgReg),
		"copy-mode-indicator":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkRed),
		"copy-mode":              gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"stream-client":          gowid.MakePaletteEntry(StreamClientFg, StreamClientBg),
		"stream-server":          gowid.MakePaletteEntry(StreamServerFg, StreamServerBg),
		"stream-match":           gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"stream-search":          gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorBlack),
	}

	//======================================================================
	// Dark mode
	//

	//                                                       256 color   < 256 color
	ButtonBg                  *modeswap.Color = modeswap.New(LightGray, gowid.ColorWhite)
	PktListRowSelectedFgDark  *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	PktListRowSelectedBgDark  *modeswap.Color = modeswap.New(DarkGray, gowid.ColorWhite)
	PktListRowFocusBgDark     *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	PktListCellSelectedFgDark *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	PktListCellSelectedBgDark *modeswap.Color = modeswap.New(MediumGray, gowid.ColorWhite)
	PktStructSelectedFgDark   *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlack)
	PktStructSelectedBgDark   *modeswap.Color = modeswap.New(DarkGray, gowid.ColorWhite)
	PktStructFocusBgDark      *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	HexTopUnselectedFgDark    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorBlue)
	HexTopUnselectedBgDark    *modeswap.Color = modeswap.New(MediumGray, gowid.ColorWhite)
	HexTopSelectedFgDark      *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorWhite)
	HexTopSelectedBgDark      *modeswap.Color = modeswap.New(BrightBlue, gowid.ColorBlue)
	HexBottomUnselectedFgDark *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorBlack)
	HexBottomUnselectedBgDark *modeswap.Color = modeswap.New(DarkGray, gowid.ColorWhite)
	HexBottomSelectedFgDark   *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorBlack)
	HexBottomSelectedBgDark   *modeswap.Color = modeswap.New(DarkGray, gowid.ColorWhite)
	HexCurUnselectedFgDark    *modeswap.Color = modeswap.New(gowid.ColorWhite, gowid.ColorMagenta)
	HexCurUnselectedBgDark    *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexLineFgDark             *modeswap.Color = modeswap.New(gowid.ColorBlack, gowid.ColorWhite)
	HexLineBgDark             *modeswap.Color = modeswap.New(DarkGray, gowid.ColorBlack)
	FilterValidBgDark         *modeswap.Color = modeswap.New(BrightGreen, gowid.ColorGreen)
	ButtonBgDark              *modeswap.Color = modeswap.New(MediumGray, gowid.ColorWhite)
	StreamClientFgDark        *modeswap.Color = modeswap.New(LightRed, gowid.ColorWhite)
	StreamClientBgDark        *modeswap.Color = modeswap.New(DarkRed, gowid.ColorDarkRed)
	StreamServerFgDark        *modeswap.Color = modeswap.New(LightBlue, gowid.ColorWhite)
	StreamServerBgDark        *modeswap.Color = modeswap.New(DarkBlue, gowid.ColorBlue)

	DarkModePalette gowid.Palette = gowid.Palette{
		"default":                gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorBlack),
		"title":                  gowid.MakeForeground(gowid.ColorRed),
		"current-capture":        gowid.MakeForeground(gowid.ColorWhite),
		"pkt-list-row-focus":     gowid.MakePaletteEntry(gowid.ColorWhite, PktListRowFocusBgDark),
		"pkt-list-cell-focus":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorPurple),
		"pkt-list-row-selected":  gowid.MakePaletteEntry(PktListRowSelectedFgDark, PktListRowSelectedBgDark),
		"pkt-list-cell-selected": gowid.MakePaletteEntry(PktListCellSelectedFgDark, PktListCellSelectedBgDark),
		"pkt-struct-focus":       gowid.MakePaletteEntry(gowid.ColorWhite, PktStructFocusBgDark),
		"pkt-struct-selected":    gowid.MakePaletteEntry(PktStructSelectedFgDark, PktStructSelectedBgDark),
		"filter-menu-focus":      gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"filter-valid":           gowid.MakePaletteEntry(gowid.ColorBlack, FilterValidBgDark),
		"filter-invalid":         gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorRed),
		"filter-intermediate":    gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorOrange),
		"dialog":                 gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"dialog-buttons":         gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"button":                 gowid.MakePaletteEntry(gowid.ColorBlack, ButtonBgDark),
		"button-focus":           gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"progress-default":       gowid.MakeStyledPaletteEntry(gowid.ColorWhite, gowid.ColorBlack, gowid.StyleBold),
		"progress-complete":      gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(gowid.ColorMagenta)),
		"progress-spinner":       gowid.MakePaletteEntry(gowid.ColorYellow, gowid.ColorBlack),
		"hex-cur-selected":       gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorMagenta),
		"hex-cur-unselected":     gowid.MakePaletteEntry(HexCurUnselectedFgDark, HexCurUnselectedBgDark),
		"hex-top-selected":       gowid.MakePaletteEntry(HexTopSelectedFgDark, HexTopSelectedBgDark),
		"hex-top-unselected":     gowid.MakePaletteEntry(HexTopUnselectedFgDark, HexTopUnselectedBgDark),
		"hex-bottom-selected":    gowid.MakePaletteEntry(HexBottomSelectedFgDark, HexBottomSelectedBgDark),
		"hex-bottom-unselected":  gowid.MakePaletteEntry(HexBottomUnselectedFgDark, HexBottomUnselectedBgDark),
		"hexln-selected":         gowid.MakePaletteEntry(HexLineFgDark, HexLineBgDark),
		"hexln-unselected":       gowid.MakePaletteEntry(HexLineFgDark, HexLineBgDark),
		"copy-mode-indicator":    gowid.MakePaletteEntry(gowid.ColorWhite, gowid.ColorDarkRed),
		"copy-mode":              gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"stream-client":          gowid.MakePaletteEntry(StreamClientFgDark, StreamClientBgDark),
		"stream-server":          gowid.MakePaletteEntry(StreamServerFgDark, StreamServerBgDark),
		"stream-match":           gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorYellow),
		"stream-search":          gowid.MakePaletteEntry(gowid.ColorBlack, gowid.ColorWhite),
	}
)

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
