// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
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

	ButtonSelectedFgReg        gowid.IColor
	ButtonSelectedBgReg        gowid.IColor
	PktListRowSelectedBgReg    gowid.IColor
	PktListRowFocusBgReg       gowid.IColor
	PktListCellSelectedFgReg   gowid.IColor
	PktListCellSelectedBgReg   gowid.IColor
	PktStructSelectedBgReg     gowid.IColor
	PktStructFocusBgReg        gowid.IColor
	HexFieldUnselectedFgReg    gowid.IColor
	HexFieldUnselectedBgReg    gowid.IColor
	HexFieldSelectedFgReg      gowid.IColor
	HexFieldSelectedBgReg      gowid.IColor
	HexLayerUnselectedFgReg    gowid.IColor
	HexLayerUnselectedBgReg    gowid.IColor
	HexLayerSelectedFgReg      gowid.IColor
	HexLayerSelectedBgReg      gowid.IColor
	HexByteUnselectedFgReg     gowid.IColor
	HexByteUnselectedBgReg     gowid.IColor
	HexIntervalSelectedFgReg   gowid.IColor
	HexIntervalSelectedBgReg   gowid.IColor
	HexIntervalUnselectedFgReg gowid.IColor
	HexIntervalUnselectedBgReg gowid.IColor
	FilterValidBgReg           gowid.IColor
	StreamClientFg             gowid.IColor
	StreamClientBg             gowid.IColor
	StreamServerFg             gowid.IColor
	StreamServerBg             gowid.IColor

	RegularPalette gowid.Palette

	//======================================================================
	// Dark mode
	//

	ButtonSelectedFgDark        gowid.IColor
	ButtonSelectedBgDark        gowid.IColor
	ButtonBgReg                 gowid.IColor
	PktListRowSelectedFgDark    gowid.IColor
	PktListRowSelectedBgDark    gowid.IColor
	PktListRowFocusBgDark       gowid.IColor
	PktListCellSelectedFgDark   gowid.IColor
	PktListCellSelectedBgDark   gowid.IColor
	PktStructSelectedFgDark     gowid.IColor
	PktStructSelectedBgDark     gowid.IColor
	PktStructFocusBgDark        gowid.IColor
	HexFieldUnselectedFgDark    gowid.IColor
	HexFieldUnselectedBgDark    gowid.IColor
	HexFieldSelectedFgDark      gowid.IColor
	HexFieldSelectedBgDark      gowid.IColor
	HexLayerUnselectedFgDark    gowid.IColor
	HexLayerUnselectedBgDark    gowid.IColor
	HexLayerSelectedFgDark      gowid.IColor
	HexLayerSelectedBgDark      gowid.IColor
	HexByteUnselectedFgDark     gowid.IColor
	HexByteUnselectedBgDark     gowid.IColor
	HexIntervalSelectedBgDark   gowid.IColor
	HexIntervalSelectedFgDark   gowid.IColor
	HexIntervalUnselectedBgDark gowid.IColor
	HexIntervalUnselectedFgDark gowid.IColor
	FilterValidBgDark           gowid.IColor
	ButtonBgDark                gowid.IColor
	StreamClientFgDark          gowid.IColor
	StreamClientBgDark          gowid.IColor
	StreamServerFgDark          gowid.IColor
	StreamServerBgDark          gowid.IColor

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
	ButtonBgReg = lbg("button", modeswap.New(LightGray, LightGray, gowid.ColorWhite))
	ButtonSelectedFgReg = lfg("button-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorWhite))
	ButtonSelectedBgReg = lbg("button-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorBlack))
	PktListRowSelectedBgReg = lbg("packet-list-row-selected", modeswap.New(MediumGray, MediumGray, gowid.ColorBlack))
	PktListRowFocusBgReg = lbg("packet-list-row-focus", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	PktListCellSelectedFgReg = lfg("packet-list-cell-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorWhite))
	PktListCellSelectedBgReg = lbg("packet-list-cell-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorBlack))
	PktStructSelectedBgReg = lbg("packet-struct-selected", modeswap.New(MediumGray, MediumGray, gowid.ColorBlack))
	PktStructFocusBgReg = lbg("packet-struct-focus", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	HexFieldUnselectedFgReg = lfg("hex-field-unselected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorWhite))
	HexFieldUnselectedBgReg = lbg("hex-field-unselected", modeswap.New(MediumGray, MediumGray, gowid.ColorBlack))
	HexFieldSelectedFgReg = lfg("hex-field-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorWhite))
	HexFieldSelectedBgReg = lbg("hex-field-selected", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	HexLayerUnselectedFgReg = lfg("hex-layer-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexLayerUnselectedBgReg = lbg("hex-layer-unselected", modeswap.New(LightGray, LightGray, gowid.ColorBlack))
	HexLayerSelectedFgReg = lfg("hex-layer-selected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexLayerSelectedBgReg = lbg("hex-layer-selected", modeswap.New(LightGray, LightGray, gowid.ColorBlack))
	HexByteUnselectedFgReg = lfg("hex-byte-unselected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlack))
	HexByteUnselectedBgReg = lbg("hex-byte-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalSelectedFgReg = lfg("hex-interval-selected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalSelectedBgReg = lbg("hex-interval-selected", modeswap.New(LightGray, LightGray, gowid.ColorBlack))
	HexIntervalUnselectedFgReg = lfg("hex-interval-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalUnselectedBgReg = lbg("hex-interval-unselected", modeswap.New(LightGray, LightGray, gowid.ColorBlack))
	FilterValidBgReg = lbg("filter-valid", modeswap.New(BrightGreen, BrightGreen, gowid.ColorGreen))
	StreamClientFg = lfg("stream-client", modeswap.New(DarkRed, DarkRed, gowid.ColorWhite))
	StreamClientBg = lbg("stream-client", modeswap.New(LightRed, LightRed, gowid.ColorDarkRed))
	StreamServerFg = lfg("stream-server", modeswap.New(DarkBlue, DarkBlue, gowid.ColorWhite))
	StreamServerBg = lbg("stream-server", modeswap.New(LightBlue, LightBlue, gowid.ColorBlue))

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
	ButtonBgDark = dbg("button", modeswap.New(MediumGray, MediumGray, gowid.ColorWhite))
	ButtonSelectedFgDark = dfg("button-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlack))
	ButtonSelectedBgDark = dbg("button-selected", modeswap.New(MediumGray, MediumGray, gowid.ColorWhite))
	PktListRowSelectedFgDark = dfg("packet-list-row-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlack))
	PktListRowSelectedBgDark = dbg("packet-list-row-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorWhite))
	PktListRowFocusBgDark = dbg("packet-list-row-focus", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	PktListCellSelectedFgDark = dfg("packet-list-cell-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlack))
	PktListCellSelectedBgDark = dbg("packet-list-cell-selected", modeswap.New(MediumGray, MediumGray, gowid.ColorWhite))
	PktStructSelectedFgDark = dfg("packet-struct-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlack))
	PktStructSelectedBgDark = dbg("packet-struct-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorWhite))
	PktStructFocusBgDark = dbg("packet-struct-focus", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	HexFieldUnselectedFgDark = dfg("hex-field-unselected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorBlue))
	HexFieldUnselectedBgDark = dbg("hex-field-unselected", modeswap.New(MediumGray, MediumGray, gowid.ColorWhite))
	HexFieldSelectedFgDark = dfg("hex-field-selected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorWhite))
	HexFieldSelectedBgDark = dbg("hex-field-selected", modeswap.New(BrightBlue, BrightBlue, gowid.ColorBlue))
	HexLayerUnselectedFgDark = dfg("hex-layer-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorBlack))
	HexLayerUnselectedBgDark = dbg("hex-layer-unselected", modeswap.New(DarkGray, DarkGray, gowid.ColorWhite))
	HexLayerSelectedFgDark = dfg("hex-layer-selected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorBlack))
	HexLayerSelectedBgDark = dbg("hex-layer-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorWhite))
	HexByteUnselectedFgDark = dfg("hex-byte-unselected", modeswap.New(gowid.ColorWhite, gowid.ColorWhite, gowid.ColorMagenta))
	HexByteUnselectedBgDark = dbg("hex-byte-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalSelectedFgDark = dfg("hex-interval-selected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalSelectedBgDark = dbg("hex-interval-selected", modeswap.New(DarkGray, DarkGray, gowid.ColorBlack))
	HexIntervalUnselectedFgDark = dfg("hex-interval-unselected", modeswap.New(gowid.ColorBlack, gowid.ColorBlack, gowid.ColorWhite))
	HexIntervalUnselectedBgDark = dbg("hex-interval-unselected", modeswap.New(DarkGray, DarkGray, gowid.ColorBlack))
	FilterValidBgDark = dbg("filter-valid", modeswap.New(BrightGreen, BrightGreen, gowid.ColorGreen))
	StreamClientFgDark = dfg("stream-client", modeswap.New(LightRed, LightRed, gowid.ColorWhite))
	StreamClientBgDark = dbg("stream-client", modeswap.New(DarkRed, DarkRed, gowid.ColorDarkRed))
	StreamServerFgDark = dfg("stream-server", modeswap.New(LightBlue, LightBlue, gowid.ColorWhite))
	StreamServerBgDark = dbg("stream-server", modeswap.New(DarkBlue, DarkBlue, gowid.ColorBlue))

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
		// color can't be resolved. When this is called, we should always have a
		// theme loaded because we fall back to the "default" theme if no other is
		// specified.
		log.Warnf("Could not understand configured theme color '%s'", key)
	}

	return fb
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
