// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2/pkg/theme"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var (
	RegularPalette  gowid.Palette
	DarkModePalette gowid.Palette
)

func SetupColors() {
	//======================================================================
	// Regular mode
	//

	RegularPalette = gowid.Palette{
		"default":                   gowid.MakePaletteEntry(lfg("default"), lbg("default")),
		"title":                     gowid.MakeForeground(lfg("title")),
		"packet-list-row-focus":     gowid.MakePaletteEntry(lfg("packet-list-row-focus"), lbg("packet-list-row-focus")),
		"packet-list-row-selected":  gowid.MakePaletteEntry(lfg("packet-list-row-selected"), lbg("packet-list-row-selected")),
		"packet-list-cell-focus":    gowid.MakePaletteEntry(lfg("packet-list-cell-focus"), lbg("packet-list-cell-focus")),
		"packet-list-cell-selected": gowid.MakePaletteEntry(lfg("packet-list-cell-selected"), lbg("packet-list-cell-selected")),
		"packet-struct-focus":       gowid.MakePaletteEntry(lfg("packet-struct-focus"), lbg("packet-struct-focus")),
		"packet-struct-selected":    gowid.MakePaletteEntry(lfg("packet-struct-selected"), lbg("packet-struct-selected")),
		"filter-menu":               gowid.MakeStyledPaletteEntry(lfg("filter-menu"), lbg("filter-menu"), gowid.StyleBold),
		"filter-valid":              gowid.MakePaletteEntry(lfg("filter-valid"), lbg("filter-valid")),
		"filter-invalid":            gowid.MakePaletteEntry(lfg("filter-invalid"), lbg("filter-invalid")),
		"filter-intermediate":       gowid.MakePaletteEntry(lfg("filter-intermediate"), lbg("filter-intermediate")),
		"filter-empty":              gowid.MakePaletteEntry(dfg("filter-empty"), dbg("filter-empty")),
		"dialog":                    gowid.MakePaletteEntry(lfg("dialog"), lbg("dialog")),
		"dialog-button":             gowid.MakePaletteEntry(lfg("dialog-button"), lbg("dialog-button")),
		"cmdline":                   gowid.MakePaletteEntry(lfg("cmdline"), lbg("cmdline")),
		"cmdline-button":            gowid.MakePaletteEntry(lfg("cmdline-button"), lbg("cmdline-button")),
		"cmdline-border":            gowid.MakePaletteEntry(lfg("cmdline-border"), lbg("cmdline-border")),
		"button":                    gowid.MakePaletteEntry(lfg("button"), lbg("button")),
		"button-focus":              gowid.MakePaletteEntry(lfg("button-focus"), lbg("button-focus")),
		"button-selected":           gowid.MakePaletteEntry(lfg("button-selected"), lbg("button-selected")),
		"progress-default":          gowid.MakeStyledPaletteEntry(lfg("progress-default"), lbg("progress-default"), gowid.StyleBold),
		"progress-complete":         gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(lbg("progress-complete"))),
		"progress-spinner":          gowid.MakePaletteEntry(lfg("progress-spinner"), lbg("progress-spinner")),
		"hex-byte-selected":         gowid.MakePaletteEntry(lfg("hex-byte-selected"), lbg("hex-byte-selected")),
		"hex-byte-unselected":       gowid.MakePaletteEntry(lfg("hex-byte-unselected"), lbg("hex-byte-unselected")),
		"hex-field-selected":        gowid.MakePaletteEntry(lfg("hex-field-selected"), lbg("hex-field-selected")),
		"hex-field-unselected":      gowid.MakePaletteEntry(lfg("hex-field-unselected"), lbg("hex-field-unselected")),
		"hex-layer-selected":        gowid.MakePaletteEntry(lfg("hex-layer-selected"), lbg("hex-layer-selected")),
		"hex-layer-unselected":      gowid.MakePaletteEntry(lfg("hex-layer-unselected"), lbg("hex-layer-unselected")),
		"hex-interval-selected":     gowid.MakePaletteEntry(lfg("hex-interval-selected"), lbg("hex-interval-selected")),
		"hex-interval-unselected":   gowid.MakePaletteEntry(lfg("hex-interval-unselected"), lbg("hex-interval-unselected")),
		"copy-mode-label":           gowid.MakePaletteEntry(lfg("copy-mode-label"), lbg("copy-mode-label")),
		"copy-mode":                 gowid.MakePaletteEntry(lfg("copy-mode"), lbg("copy-mode")),
		"copy-mode-alt":             gowid.MakePaletteEntry(lfg("copy-mode-alt"), lbg("copy-mode-alt")),
		"stream-client":             gowid.MakePaletteEntry(lfg("stream-client"), lbg("stream-client")),
		"stream-server":             gowid.MakePaletteEntry(lfg("stream-server"), lbg("stream-server")),
		"stream-match":              gowid.MakePaletteEntry(lfg("stream-match"), lbg("stream-match")),
		"stream-search":             gowid.MakePaletteEntry(lfg("stream-search"), lbg("stream-search")),
	}

	//======================================================================
	// Dark mode
	//

	DarkModePalette = gowid.Palette{
		"default":                   gowid.MakePaletteEntry(dfg("default"), dbg("default")),
		"title":                     gowid.MakeForeground(dfg("title")),
		"current-capture":           gowid.MakeForeground(dfg("current-capture")),
		"packet-list-row-focus":     gowid.MakePaletteEntry(dfg("packet-list-row-focus"), dbg("packet-list-row-focus")),
		"packet-list-row-selected":  gowid.MakePaletteEntry(dfg("packet-list-row-selected"), dbg("packet-list-row-selected")),
		"packet-list-cell-focus":    gowid.MakePaletteEntry(dfg("packet-list-cell-focus"), dbg("packet-list-cell-focus")),
		"packet-list-cell-selected": gowid.MakePaletteEntry(dfg("packet-list-cell-selected"), dbg("packet-list-cell-selected")),
		"packet-struct-focus":       gowid.MakePaletteEntry(dfg("packet-struct-focus"), dbg("packet-struct-focus")),
		"packet-struct-selected":    gowid.MakePaletteEntry(dfg("packet-struct-selected"), dbg("packet-struct-selected")),
		"filter-menu":               gowid.MakeStyledPaletteEntry(dfg("filter-menu"), dbg("filter-menu"), gowid.StyleBold),
		"filter-valid":              gowid.MakePaletteEntry(dfg("filter-valid"), dbg("filter-valid")),
		"filter-invalid":            gowid.MakePaletteEntry(dfg("filter-invalid"), dbg("filter-invalid")),
		"filter-intermediate":       gowid.MakePaletteEntry(dfg("filter-intermediate"), dbg("filter-intermediate")),
		"filter-empty":              gowid.MakePaletteEntry(dfg("filter-empty"), dbg("filter-empty")),
		"dialog":                    gowid.MakePaletteEntry(dfg("dialog"), dbg("dialog")),
		"dialog-button":             gowid.MakePaletteEntry(dfg("dialog-button"), dbg("dialog-button")),
		"cmdline":                   gowid.MakePaletteEntry(dfg("cmdline"), dbg("cmdline")),
		"cmdline-button":            gowid.MakePaletteEntry(dfg("cmdline-button"), dbg("cmdline-button")),
		"cmdline-border":            gowid.MakePaletteEntry(dfg("cmdline-border"), dbg("cmdline-border")),
		"button":                    gowid.MakePaletteEntry(dfg("button"), dbg("button")),
		"button-focus":              gowid.MakePaletteEntry(dfg("button-focus"), dbg("button-focus")),
		"button-selected":           gowid.MakePaletteEntry(dfg("button-selected"), dbg("button-selected")),
		"progress-default":          gowid.MakeStyledPaletteEntry(dfg("progress-default"), dbg("progress-default"), gowid.StyleBold),
		"progress-complete":         gowid.MakeStyleMod(gowid.MakePaletteRef("progress-default"), gowid.MakeBackground(dbg("progress-complete"))),
		"progress-spinner":          gowid.MakePaletteEntry(dfg("spinner"), dbg("spinner")),
		"hex-byte-selected":         gowid.MakeStyledPaletteEntry(dfg("hex-byte-selected"), dbg("hex-byte-selected"), gowid.StyleBold),
		"hex-byte-unselected":       gowid.MakeStyledPaletteEntry(dfg("hex-byte-unselected"), dbg("hex-byte-unselected"), gowid.StyleBold),
		"hex-field-selected":        gowid.MakePaletteEntry(dfg("hex-field-selected"), dbg("hex-field-selected")),
		"hex-field-unselected":      gowid.MakePaletteEntry(dfg("hex-field-unselected"), dbg("hex-field-unselected")),
		"hex-layer-selected":        gowid.MakePaletteEntry(dfg("hex-layer-selected"), dbg("hex-layer-selected")),
		"hex-layer-unselected":      gowid.MakePaletteEntry(dfg("hex-layer-unselected"), dbg("hex-layer-unselected")),
		"hex-interval-selected":     gowid.MakePaletteEntry(dfg("hex-interval-selected"), dbg("hex-interval-selected")),
		"hex-interval-unselected":   gowid.MakePaletteEntry(dfg("hex-interval-unselected"), dbg("hex-interval-unselected")),
		"stream-client":             gowid.MakePaletteEntry(dfg("stream-client"), dbg("stream-client")),
		"stream-server":             gowid.MakePaletteEntry(dfg("stream-server"), dbg("stream-server")),
		"copy-mode-label":           gowid.MakePaletteEntry(dfg("copy-mode-label"), dbg("copy-mode-label")),
		"copy-mode":                 gowid.MakePaletteEntry(dfg("copy-mode"), dbg("copy-mode")),
		"copy-mode-alt":             gowid.MakePaletteEntry(dfg("copy-mode-alt"), dbg("copy-mode-alt")),
		"stream-match":              gowid.MakePaletteEntry(dfg("stream-match"), dbg("stream-match")),
		"stream-search":             gowid.MakePaletteEntry(dfg("stream-search"), dbg("stream-search")),
	}

}

func dfg(key string) gowid.IColor {
	return tomlCol(key, theme.Foreground, "dark")
}

func dbg(key string) gowid.IColor {
	return tomlCol(key, theme.Background, "dark")
}

func lfg(key string) gowid.IColor {
	return tomlCol(key, theme.Foreground, "light")
}

func lbg(key string) gowid.IColor {
	return tomlCol(key, theme.Background, "light")
}

func tomlCol(key string, layer theme.Layer, hue string) gowid.IColor {
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

	return gowid.ColorBlack
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
