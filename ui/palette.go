// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/theme"
	"github.com/gcla/termshark/v2/theme/modeswap"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var (
	LightGray   gowid.IColor
	MediumGray  gowid.IColor
	DarkGray    gowid.IColor
	BrightBlue  gowid.IColor
	BrightGreen gowid.IColor
	LightRed    gowid.IColor
	LightBlue   gowid.IColor
	DarkRed     gowid.IColor
	DarkBlue    gowid.IColor

	//======================================================================
	// Regular mode
	//

	ButtonSelectedFgReg        *modeswap.Color
	ButtonSelectedBgReg        *modeswap.Color
	PktListRowSelectedBgReg    *modeswap.Color
	PktListRowFocusBgReg       *modeswap.Color
	PktListCellSelectedFgReg   *modeswap.Color
	PktListCellSelectedBgReg   *modeswap.Color
	PktStructSelectedBgReg     *modeswap.Color
	PktStructFocusBgReg        *modeswap.Color
	HexFieldUnselectedFgReg    *modeswap.Color
	HexFieldUnselectedBgReg    *modeswap.Color
	HexFieldSelectedFgReg      *modeswap.Color
	HexFieldSelectedBgReg      *modeswap.Color
	HexLayerUnselectedFgReg    *modeswap.Color
	HexLayerUnselectedBgReg    *modeswap.Color
	HexLayerSelectedFgReg      *modeswap.Color
	HexLayerSelectedBgReg      *modeswap.Color
	HexByteUnselectedFgReg     *modeswap.Color
	HexByteUnselectedBgReg     *modeswap.Color
	HexIntervalSelectedFgReg   *modeswap.Color
	HexIntervalSelectedBgReg   *modeswap.Color
	HexIntervalUnselectedFgReg *modeswap.Color
	HexIntervalUnselectedBgReg *modeswap.Color
	FilterValidBgReg           *modeswap.Color
	StreamClientFg             *modeswap.Color
	StreamClientBg             *modeswap.Color
	StreamServerFg             *modeswap.Color
	StreamServerBg             *modeswap.Color

	RegularPalette gowid.Palette

	//======================================================================
	// Dark mode
	//

	ButtonSelectedFgDark        *modeswap.Color
	ButtonSelectedBgDark        *modeswap.Color
	ButtonBgReg                 *modeswap.Color
	PktListRowSelectedFgDark    *modeswap.Color
	PktListRowSelectedBgDark    *modeswap.Color
	PktListRowFocusBgDark       *modeswap.Color
	PktListCellSelectedFgDark   *modeswap.Color
	PktListCellSelectedBgDark   *modeswap.Color
	PktStructSelectedFgDark     *modeswap.Color
	PktStructSelectedBgDark     *modeswap.Color
	PktStructFocusBgDark        *modeswap.Color
	HexFieldUnselectedFgDark    *modeswap.Color
	HexFieldUnselectedBgDark    *modeswap.Color
	HexFieldSelectedFgDark      *modeswap.Color
	HexFieldSelectedBgDark      *modeswap.Color
	HexLayerUnselectedFgDark    *modeswap.Color
	HexLayerUnselectedBgDark    *modeswap.Color
	HexLayerSelectedFgDark      *modeswap.Color
	HexLayerSelectedBgDark      *modeswap.Color
	HexByteUnselectedFgDark     *modeswap.Color
	HexByteUnselectedBgDark     *modeswap.Color
	HexIntervalSelectedBgDark   *modeswap.Color
	HexIntervalSelectedFgDark   *modeswap.Color
	HexIntervalUnselectedBgDark *modeswap.Color
	HexIntervalUnselectedFgDark *modeswap.Color
	FilterValidBgDark           *modeswap.Color
	ButtonBgDark                *modeswap.Color
	StreamClientFgDark          *modeswap.Color
	StreamClientBgDark          *modeswap.Color
	StreamServerFgDark          *modeswap.Color
	StreamServerBgDark          *modeswap.Color

	DarkModePalette gowid.Palette
)

func SetupColors() {
	LightGray = gowid.MakeGrayColor("g74")
	MediumGray = gowid.MakeGrayColor("g50")
	DarkGray = gowid.MakeGrayColor("g35")
	BrightBlue = gowid.MakeRGBColor("#08f")
	BrightGreen = gowid.MakeRGBColor("#6f2")
	LightRed = gowid.MakeRGBColor("#ebb")
	LightBlue = gowid.MakeRGBColor("#abf")
	DarkRed = gowid.MakeRGBColor("#311")
	DarkBlue = gowid.MakeRGBColor("#01f")

	//======================================================================
	// Regular mode
	//

	//                                           256 color   < 256 color
	ButtonBgReg = modeswap.New(lbg("button", LightGray), gowid.ColorWhite)
	ButtonSelectedFgReg = modeswap.New(lfg("button-selected", gowid.ColorWhite), gowid.ColorWhite)
	ButtonSelectedBgReg = modeswap.New(lbg("button-selected", DarkGray), gowid.ColorBlack)
	PktListRowSelectedBgReg = modeswap.New(lbg("packet-list-row-selected", MediumGray), gowid.ColorBlack)
	PktListRowFocusBgReg = modeswap.New(lbg("packet-list-row-focus", BrightBlue), gowid.ColorBlue)
	PktListCellSelectedFgReg = modeswap.New(lfg("packet-list-cell-selected", gowid.ColorWhite), gowid.ColorWhite)
	PktListCellSelectedBgReg = modeswap.New(lbg("packet-list-cell-selected", DarkGray), gowid.ColorBlack)
	PktStructSelectedBgReg = modeswap.New(lbg("packet-struct-selected", MediumGray), gowid.ColorBlack)
	PktStructFocusBgReg = modeswap.New(lbg("packet-struct-focus", BrightBlue), gowid.ColorBlue)
	HexFieldUnselectedFgReg = modeswap.New(lfg("hex-field-unselected", gowid.ColorWhite), gowid.ColorWhite)
	HexFieldUnselectedBgReg = modeswap.New(lbg("hex-field-unselected", MediumGray), gowid.ColorBlack)
	HexFieldSelectedFgReg = modeswap.New(lfg("hex-field-selected", gowid.ColorWhite), gowid.ColorWhite)
	HexFieldSelectedBgReg = modeswap.New(lbg("hex-field-selected", BrightBlue), gowid.ColorBlue)
	HexLayerUnselectedFgReg = modeswap.New(lfg("hex-layer-unselected", gowid.ColorBlack), gowid.ColorWhite)
	HexLayerUnselectedBgReg = modeswap.New(lbg("hex-layer-unselected", LightGray), gowid.ColorBlack)
	HexLayerSelectedFgReg = modeswap.New(lfg("hex-layer-selected", gowid.ColorBlack), gowid.ColorWhite)
	HexLayerSelectedBgReg = modeswap.New(lbg("hex-layer-selected", LightGray), gowid.ColorBlack)
	HexByteUnselectedFgReg = modeswap.New(lfg("hex-byte-unselected", gowid.ColorWhite), gowid.ColorBlack)
	HexByteUnselectedBgReg = modeswap.New(lbg("hex-byte-unselected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalSelectedFgReg = modeswap.New(lfg("hex-interval-selected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalSelectedBgReg = modeswap.New(lbg("hex-interval-selected", LightGray), gowid.ColorBlack)
	HexIntervalUnselectedFgReg = modeswap.New(lfg("hex-interval-unselected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalUnselectedBgReg = modeswap.New(lbg("hex-interval-unselected", LightGray), gowid.ColorBlack)
	FilterValidBgReg = modeswap.New(lbg("filter-valid", BrightGreen), gowid.ColorGreen)
	StreamClientFg = modeswap.New(lfg("stream-client", DarkRed), gowid.ColorWhite)
	StreamClientBg = modeswap.New(lbg("stream-client", LightRed), gowid.ColorDarkRed)
	StreamServerFg = modeswap.New(lfg("stream-server", DarkBlue), gowid.ColorWhite)
	StreamServerBg = modeswap.New(lbg("stream-server", LightBlue), gowid.ColorBlue)

	RegularPalette = gowid.Palette{
		"default":                   gowid.MakePaletteEntry(lfg("default", gowid.ColorBlack), lbg("default", gowid.ColorWhite)),
		"title":                     gowid.MakeForeground(lfg("title", gowid.ColorDarkRed)),
		"packet-list-row-focus":     gowid.MakePaletteEntry(lfg("packet-list-row-focus", gowid.ColorWhite), lbg("packet-list-row-focus", PktListRowFocusBgReg)),
		"packet-list-row-selected":  gowid.MakePaletteEntry(lfg("packet-list-row-selected", gowid.ColorWhite), PktListRowSelectedBgReg),
		"packet-list-cell-focus":    gowid.MakePaletteEntry(lfg("packet-list-cell-focus", gowid.ColorWhite), lbg("packet-list-cell-focus", gowid.ColorPurple)),
		"packet-list-cell-selected": gowid.MakePaletteEntry(PktListCellSelectedFgReg, PktListCellSelectedBgReg),
		"packet-struct-focus":       gowid.MakePaletteEntry(lfg("packet-struct-focus", gowid.ColorWhite), PktStructFocusBgReg),
		"packet-struct-selected":    gowid.MakePaletteEntry(lfg("packet-struct-selected", gowid.ColorWhite), PktStructSelectedBgReg),
		"filter-menu":               gowid.MakeStyledPaletteEntry(lfg("filter-menu", gowid.ColorBlack), lbg("filter-menu", gowid.ColorWhite), gowid.StyleBold),
		"filter-valid":              gowid.MakePaletteEntry(lfg("filter-valid", gowid.ColorBlack), FilterValidBgReg),
		"filter-invalid":            gowid.MakePaletteEntry(lfg("filter-invalid", gowid.ColorBlack), lbg("filter-invalid", gowid.ColorRed)),
		"filter-intermediate":       gowid.MakePaletteEntry(lfg("filter-intermediate", gowid.ColorBlack), lbg("filter-intermediate", gowid.ColorOrange)),
		"dialog":                    gowid.MakePaletteEntry(lfg("dialog", gowid.ColorBlack), lbg("dialog", gowid.ColorYellow)),
		"dialog-button":             gowid.MakePaletteEntry(lfg("dialog-button", gowid.ColorYellow), lbg("dialog-button", gowid.ColorBlack)),
		"cmdline":                   gowid.MakePaletteEntry(lfg("cmdline", gowid.ColorBlack), lbg("cmdline", gowid.ColorYellow)),
		"cmdline-button":            gowid.MakePaletteEntry(lfg("cmdline-button", gowid.ColorYellow), lbg("cmdline-button", gowid.ColorBlack)),
		"cmdline-border":            gowid.MakePaletteEntry(lfg("cmdline-border", gowid.ColorBlack), lbg("cmdline-border", gowid.ColorYellow)),
		"button":                    gowid.MakePaletteEntry(lfg("button", gowid.ColorDarkBlue), ButtonBgReg),
		"button-focus":              gowid.MakePaletteEntry(lfg("button-focus", gowid.ColorWhite), lbg("button-focus", gowid.ColorDarkBlue)),
		"button-selected":           gowid.MakePaletteEntry(ButtonSelectedFgReg, ButtonSelectedBgReg),
		"progress-default":          gowid.MakeStyledPaletteEntry(lfg("progress-default", gowid.ColorWhite), lbg("progress-default", gowid.ColorBlack), gowid.StyleBold),
		"progress-complete":         gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(lbg("progress-complete", gowid.ColorMagenta))),
		"progress-spinner":          gowid.MakePaletteEntry(lfg("progress-spinner", gowid.ColorYellow), lbg("progress-spinner", gowid.ColorBlack)),
		"hex-byte-selected":         gowid.MakePaletteEntry(lfg("hex-byte-selected", gowid.ColorWhite), lbg("hex-byte-selected", gowid.ColorMagenta)),
		"hex-byte-unselected":       gowid.MakePaletteEntry(HexByteUnselectedFgReg, HexByteUnselectedBgReg),
		"hex-field-selected":        gowid.MakePaletteEntry(HexFieldSelectedFgReg, HexFieldSelectedBgReg),
		"hex-field-unselected":      gowid.MakePaletteEntry(HexFieldUnselectedFgReg, HexFieldUnselectedBgReg),
		"hex-layer-selected":        gowid.MakePaletteEntry(HexLayerSelectedFgReg, HexLayerSelectedBgReg),
		"hex-layer-unselected":      gowid.MakePaletteEntry(HexLayerUnselectedFgReg, HexLayerUnselectedBgReg),
		"hex-interval-selected":     gowid.MakePaletteEntry(HexIntervalSelectedFgReg, HexIntervalSelectedBgReg),
		"hex-interval-unselected":   gowid.MakePaletteEntry(HexIntervalUnselectedFgReg, HexIntervalUnselectedBgReg),
		"copy-mode-label":           gowid.MakePaletteEntry(lfg("copy-mode-label", gowid.ColorWhite), lbg("copy-mode-label", gowid.ColorDarkRed)),
		"copy-mode":                 gowid.MakePaletteEntry(lfg("copy-mode", gowid.ColorBlack), lbg("copy-mode", gowid.ColorYellow)),
		"copy-mode-alt":             gowid.MakePaletteEntry(lfg("copy-mode-alt", gowid.ColorYellow), lbg("copy-mode-alt", gowid.ColorBlack)),
		"stream-client":             gowid.MakePaletteEntry(StreamClientFg, StreamClientBg),
		"stream-server":             gowid.MakePaletteEntry(StreamServerFg, StreamServerBg),
		"stream-match":              gowid.MakePaletteEntry(lfg("stream-match", gowid.ColorBlack), lbg("stream-match", gowid.ColorYellow)),
		"stream-search":             gowid.MakePaletteEntry(lfg("stream-search", gowid.ColorWhite), lbg("stream-search", gowid.ColorBlack)),
	}

	//======================================================================
	// Dark mode
	//

	//                                            256 color   < 256 color
	ButtonBgDark = modeswap.New(dbg("button", MediumGray), gowid.ColorWhite)
	ButtonSelectedFgDark = modeswap.New(dfg("button-selected", gowid.ColorWhite), gowid.ColorBlack)
	ButtonSelectedBgDark = modeswap.New(dbg("button-selected", MediumGray), gowid.ColorWhite)
	PktListRowSelectedFgDark = modeswap.New(dfg("packet-list-row-selected", gowid.ColorWhite), gowid.ColorBlack)
	PktListRowSelectedBgDark = modeswap.New(dbg("packet-list-row-selected", DarkGray), gowid.ColorWhite)
	PktListRowFocusBgDark = modeswap.New(dbg("packet-list-row-focus", BrightBlue), gowid.ColorBlue)
	PktListCellSelectedFgDark = modeswap.New(dfg("packet-list-cell-selected", gowid.ColorWhite), gowid.ColorBlack)
	PktListCellSelectedBgDark = modeswap.New(dbg("packet-list-cell-selected", MediumGray), gowid.ColorWhite)
	PktStructSelectedFgDark = modeswap.New(dfg("packet-struct-selected", gowid.ColorWhite), gowid.ColorBlack)
	PktStructSelectedBgDark = modeswap.New(dbg("packet-struct-selected", DarkGray), gowid.ColorWhite)
	PktStructFocusBgDark = modeswap.New(dbg("packet-struct-focus", BrightBlue), gowid.ColorBlue)
	HexFieldUnselectedFgDark = modeswap.New(dfg("hex-field-unselected", gowid.ColorWhite), gowid.ColorBlue)
	HexFieldUnselectedBgDark = modeswap.New(dbg("hex-field-unselected", MediumGray), gowid.ColorWhite)
	HexFieldSelectedFgDark = modeswap.New(dfg("hex-field-selected", gowid.ColorWhite), gowid.ColorWhite)
	HexFieldSelectedBgDark = modeswap.New(dbg("hex-field-selected", BrightBlue), gowid.ColorBlue)
	HexLayerUnselectedFgDark = modeswap.New(dfg("hex-layer-unselected", gowid.ColorBlack), gowid.ColorBlack)
	HexLayerUnselectedBgDark = modeswap.New(dbg("hex-layer-unselected", DarkGray), gowid.ColorWhite)
	HexLayerSelectedFgDark = modeswap.New(dfg("hex-layer-selected", gowid.ColorBlack), gowid.ColorBlack)
	HexLayerSelectedBgDark = modeswap.New(dbg("hex-layer-selected", DarkGray), gowid.ColorWhite)
	HexByteUnselectedFgDark = modeswap.New(dfg("hex-byte-unselected", gowid.ColorWhite), gowid.ColorMagenta)
	HexByteUnselectedBgDark = modeswap.New(dbg("hex-byte-unselected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalSelectedFgDark = modeswap.New(dfg("hex-interval-selected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalSelectedBgDark = modeswap.New(dbg("hex-interval-selected", DarkGray), gowid.ColorBlack)
	HexIntervalUnselectedFgDark = modeswap.New(dfg("hex-interval-unselected", gowid.ColorBlack), gowid.ColorWhite)
	HexIntervalUnselectedBgDark = modeswap.New(dbg("hex-interval-unselected", DarkGray), gowid.ColorBlack)
	FilterValidBgDark = modeswap.New(dbg("filter-valid", BrightGreen), gowid.ColorGreen)
	StreamClientFgDark = modeswap.New(dfg("stream-client", LightRed), gowid.ColorWhite)
	StreamClientBgDark = modeswap.New(dbg("stream-client", DarkRed), gowid.ColorDarkRed)
	StreamServerFgDark = modeswap.New(dfg("stream-server", LightBlue), gowid.ColorWhite)
	StreamServerBgDark = modeswap.New(dbg("stream-server", DarkBlue), gowid.ColorBlue)

	DarkModePalette = gowid.Palette{
		"default":                   gowid.MakePaletteEntry(dfg("default", gowid.ColorWhite), dbg("default", gowid.ColorBlack)),
		"title":                     gowid.MakeForeground(dfg("title", gowid.ColorRed)),
		"current-capture":           gowid.MakeForeground(dfg("current-capture", gowid.ColorWhite)),
		"packet-list-row-focus":     gowid.MakePaletteEntry(dfg("packet-list-row-focus", gowid.ColorWhite), PktListRowFocusBgDark),
		"packet-list-row-selected":  gowid.MakePaletteEntry(PktListRowSelectedFgDark, PktListRowSelectedBgDark),
		"packet-list-cell-focus":    gowid.MakePaletteEntry(dfg("packet-list-cell-focus", gowid.ColorWhite), dbg("packet-list-cell-focus", gowid.ColorPurple)),
		"packet-list-cell-selected": gowid.MakePaletteEntry(PktListCellSelectedFgDark, PktListCellSelectedBgDark),
		"packet-struct-focus":       gowid.MakePaletteEntry(dfg("packet-struct-focus", gowid.ColorWhite), PktStructFocusBgDark),
		"packet-struct-selected":    gowid.MakePaletteEntry(PktStructSelectedFgDark, PktStructSelectedBgDark),
		"filter-menu":               gowid.MakeStyledPaletteEntry(dfg("filter-menu", gowid.ColorWhite), dbg("filter-menu", gowid.ColorBlack), gowid.StyleBold),
		"filter-valid":              gowid.MakePaletteEntry(dfg("filter-valid", gowid.ColorBlack), FilterValidBgDark),
		"filter-invalid":            gowid.MakePaletteEntry(dfg("filter-invalid", gowid.ColorBlack), dbg("filter-invalid", gowid.ColorRed)),
		"filter-intermediate":       gowid.MakePaletteEntry(dfg("filter-intermediate", gowid.ColorBlack), dbg("filter-intermediate", gowid.ColorOrange)),
		"dialog":                    gowid.MakePaletteEntry(dfg("dialog", gowid.ColorBlack), dbg("dialog", gowid.ColorYellow)),
		"dialog-button":             gowid.MakePaletteEntry(dfg("dialog-button", gowid.ColorYellow), dbg("dialog-button", gowid.ColorBlack)),
		"cmdline":                   gowid.MakePaletteEntry(dfg("cmdline", gowid.ColorBlack), dbg("cmdline", gowid.ColorYellow)),
		"cmdline-button":            gowid.MakePaletteEntry(dfg("cmdline-button", gowid.ColorYellow), dbg("cmdline-button", gowid.ColorBlack)),
		"cmdline-border":            gowid.MakePaletteEntry(dfg("cmdline-border", gowid.ColorBlack), dbg("cmdline-border", gowid.ColorYellow)),
		"button":                    gowid.MakePaletteEntry(dfg("button", gowid.ColorBlack), ButtonBgDark),
		"button-focus":              gowid.MakePaletteEntry(dfg("button-focus", gowid.ColorWhite), dbg("button-focus", gowid.ColorMagenta)),
		"button-selected":           gowid.MakePaletteEntry(ButtonSelectedFgDark, ButtonSelectedBgDark),
		"progress-default":          gowid.MakeStyledPaletteEntry(dfg("progress-default", gowid.ColorWhite), dbg("progress-default", gowid.ColorBlack), gowid.StyleBold),
		"progress-complete":         gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(dbg("progress-complete", gowid.ColorMagenta))),
		"progress-spinner":          gowid.MakePaletteEntry(dfg("spinner", gowid.ColorYellow), dbg("spinner", gowid.ColorBlack)),
		"hex-byte-selected":         gowid.MakePaletteEntry(dfg("hex-byte-selected", gowid.ColorWhite), dbg("hex-byte-selected", gowid.ColorMagenta)),
		"hex-byte-unselected":       gowid.MakePaletteEntry(HexByteUnselectedFgDark, HexByteUnselectedBgDark),
		"hex-field-selected":        gowid.MakePaletteEntry(HexFieldSelectedFgDark, HexFieldSelectedBgDark),
		"hex-field-unselected":      gowid.MakePaletteEntry(HexFieldUnselectedFgDark, HexFieldUnselectedBgDark),
		"hex-layer-selected":        gowid.MakePaletteEntry(HexLayerSelectedFgDark, HexLayerSelectedBgDark),
		"hex-layer-unselected":      gowid.MakePaletteEntry(HexLayerUnselectedFgDark, HexLayerUnselectedBgDark),
		"hex-interval-selected":     gowid.MakePaletteEntry(HexIntervalSelectedFgDark, HexIntervalSelectedBgDark),
		"hex-interval-unselected":   gowid.MakePaletteEntry(HexIntervalUnselectedFgDark, HexIntervalUnselectedBgDark),
		"copy-mode-label":           gowid.MakePaletteEntry(dfg("copy-mode-label", gowid.ColorWhite), dbg("copy-mode-label", gowid.ColorDarkRed)),
		"copy-mode":                 gowid.MakePaletteEntry(dfg("copy-mode", gowid.ColorBlack), dbg("copy-mode", gowid.ColorYellow)),
		"copy-mode-alt":             gowid.MakePaletteEntry(dfg("copy-mode-alt", gowid.ColorYellow), dbg("copy-mode-alt", gowid.ColorBlack)),
		"stream-client":             gowid.MakePaletteEntry(StreamClientFgDark, StreamClientBgDark),
		"stream-server":             gowid.MakePaletteEntry(StreamServerFgDark, StreamServerBgDark),
		"stream-match":              gowid.MakePaletteEntry(dfg("stream-match", gowid.ColorBlack), dbg("stream-match", gowid.ColorYellow)),
		"stream-search":             gowid.MakePaletteEntry(dfg("stream-search", gowid.ColorBlack), dbg("stream-search", gowid.ColorWhite)),
	}

}

func dfg(key string, fb gowid.IColor) gowid.IColor {
	return tomlCol(key, theme.Foreground, "dark", fb)
}

func dbg(key string, fb gowid.IColor) gowid.IColor {
	return tomlCol(key, theme.Background, "dark", fb)
}

func lfg(key string, fb gowid.IColor) gowid.IColor {
	return tomlCol(key, theme.Foreground, "light", fb)
}

func lbg(key string, fb gowid.IColor) gowid.IColor {
	return tomlCol(key, theme.Background, "light", fb)
}

func tomlCol(key string, layer theme.Layer, hue string, fb gowid.IColor) gowid.IColor {
	rule := fmt.Sprintf("%s.%s", hue, key)
	col, err := theme.MakeColorSafe(rule, layer)
	if err == nil {
		return col
	} else {
		// Warn if the user has defined themes.rules.etcetc, but the resulting
		// color can't be resolved. If no key is present, it means the user hasn't
		// set up themes, so ignore.
		if termshark.ConfString("main.theme", "") != "" {
			log.Infof("Could not understand configured theme color '%s'", key)
		}
	}

	return fb
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
