// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"reflect"
	"sort"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/shark"
	"github.com/gcla/termshark/v2/shark/wiresharkcfg"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gdamore/tcell"
)

//======================================================================

var colNamesMenu *menu.Widget
var colFieldsMenu *menu.Widget

// These are global variables used to hold the current model for the edit-columns
// widget, and the current line selected. This is hacky but it's so that I can tell,
// when a menu button is clicked within this PSML columns widget, which column
// it should apply to. I could generate unique menus for each row of the table, as
// an alternative...
var colsCurrentModel *psmlColumnsModel
var colsCurrentModelRow int

var colNamesMenuListBoxHolder *holder.Widget
var colFieldsMenuListBoxHolder *holder.Widget

//======================================================================

func buildNamesMenu(app gowid.IApp) {
	colNamesMenuListBoxHolder = holder.New(null.New())

	wid, hei := rebuildPsmlNamesListBox(colsCurrentModel, app)

	colNamesMenu = menu.New("psmlcols", colNamesMenuListBoxHolder, gowid.RenderWithUnits{U: wid}, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	colNamesMenu.SetHeight(units(hei), app)
}

func buildFieldsMenu(app gowid.IApp) {
	colFieldsMenuListBoxHolder = holder.New(null.New())

	wid, hei := rebuildPsmlFieldListBox(app)

	colFieldsMenu = menu.New("psmlfieldscols", colFieldsMenuListBoxHolder, gowid.RenderWithUnits{U: wid}, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})
	colFieldsMenu.SetHeight(units(hei), app)
}

type psmlColumnInfoArraySortLong []shark.PsmlColumnInfo

func (a psmlColumnInfoArraySortLong) Len() int {
	return len(a)
}
func (a psmlColumnInfoArraySortLong) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a psmlColumnInfoArraySortLong) Less(i, j int) bool {
	return a[i].Long < a[j].Long
}

// return width needed
func rebuildPsmlNamesListBox(p *psmlColumnsModel, app gowid.IApp) (int, int) {
	colsMenuItems := make([]menuutil.SimpleMenuItem, 0)

	specs := make(psmlColumnInfoArraySortLong, 0)

	for _, v := range shark.AllowedColumnFormats {
		specs = append(specs, v)
	}
	sort.Sort(specs)

	for _, spec := range specs {
		speccopy := spec
		colsMenuItems = append(colsMenuItems,
			menuutil.SimpleMenuItem{
				Txt: spec.Long,
				CB: func(app gowid.IApp, w gowid.IWidget) {
					colNamesMenu.Close(app)
					p.UpdateFromField(speccopy.Field, colsCurrentModelRow)
					app.Sync()
				},
			},
		)
	}

	colsMenuListBox, wid := menuutil.MakeMenu(colsMenuItems)
	colNamesMenuListBoxHolder.SetSubWidget(colsMenuListBox, nil)

	return wid, len(specs)
}

func rebuildPsmlFieldListBox(app gowid.IApp) (int, int) {
	p := colsCurrentModel

	colsMenuItems := make([]menuutil.SimpleMenuItem, 0)

	columnNames := make([]string, 0)
	for k, _ := range shark.AllowedColumnFormats {
		columnNames = append(columnNames, k)
	}
	sort.Strings(columnNames)

	for _, cname := range columnNames {
		cname2 := cname
		colsMenuItems = append(colsMenuItems,
			menuutil.SimpleMenuItem{
				Txt: cname,
				CB: func(app gowid.IApp, w gowid.IWidget) {
					colFieldsMenu.Close(app)
					p.UpdateFromField(cname2, colsCurrentModelRow)
					app.Sync()
				},
			},
		)
	}

	colsMenuListBox, wid := menuutil.MakeMenu(colsMenuItems)
	colFieldsMenuListBoxHolder.SetSubWidget(colsMenuListBox, nil)

	return wid, len(columnNames)
}

//======================================================================

func openEditColumns(app gowid.IApp) {
	pcols := NewPsmlColumnsModel()
	colsCurrentModel = pcols

	var mainw gowid.IWidget

	newPsmlCol := button.New(text.New("+"))
	newPsmlCol.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		pcols.AddRow()
	}))

	newPsmlColStyled := hpadding.New(clicktracker.New(
		styled.NewExt(
			newPsmlCol,
			gowid.MakePaletteRef("button"),
			gowid.MakePaletteRef("button-focus"),
		),
	), gowid.HAlignLeft{}, gowid.RenderFixed{})

	colWidgets := make([]interface{}, 0)

	pileWidgets := make([]interface{}, 0)
	pileWidgets = append(pileWidgets, pcols, divider.NewBlank(), newPsmlColStyled)

	wcfg, err := wiresharkcfg.NewDefault()
	if err == nil {
		cols := wcfg.ColumnFormat()
		if cols != nil {
			btn := button.New(text.New("Import"))
			btn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
				newPcols := NewPsmlColumnsModel()
				err = newPcols.ReadFromWireshark()
				if err != nil {
					OpenError(err.Error(), app)
					return
				}

				*pcols = *newPcols
				pcols.Widget = table.New(pcols)
				OpenMessage("Imported column preferences from Wireshark", appView, app)
			}))

			cols := hpadding.New(
				columns.NewFixed(
					clicktracker.New(
						styled.NewExt(
							btn,
							gowid.MakePaletteRef("button"),
							gowid.MakePaletteRef("button-focus"),
						),
					),
					text.New(" from Wireshark"),
				),
				gowid.HAlignLeft{},
				gowid.RenderFixed{},
			)
			colWidgets = append(colWidgets, cols)
		}
	}

	bakCols := termshark.ConfStringSlice("main.column-format-bak", []string{})
	if len(bakCols) != 0 {
		btn := button.New(text.New("Restore"))
		btn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
			newPcols := NewPsmlColumnsModelFrom("main.column-format-bak")
			if len(newPcols.spec) == 0 {
				OpenMessage("Error: backup column-format is empty in toml file", appView, app)
				return
			}

			*pcols = *newPcols
			pcols.Widget = table.New(pcols)
			OpenMessage("Imported previous column preferences", appView, app)
		}))

		cols := hpadding.New(
			columns.NewFixed(
				clicktracker.New(
					styled.NewExt(
						btn,
						gowid.MakePaletteRef("button"),
						gowid.MakePaletteRef("button-focus"),
					),
				),
				text.New(" previous columns"),
			),
			gowid.HAlignLeft{},
			gowid.RenderFixed{},
		)
		colWidgets = append(colWidgets, cols)
	}

	restoreBtn := button.New(text.New("Restore"))
	restoreBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		*pcols = *NewDefaultPsmlColumnsModel()
		pcols.Widget = table.New(pcols)
		OpenMessage("Imported default column preferences", appView, app)
	}))

	cols := hpadding.New(
		columns.NewFixed(
			clicktracker.New(
				styled.NewExt(
					restoreBtn,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
			),
			text.New(" default columns"),
		),
		gowid.HAlignLeft{},
		gowid.RenderFixed{},
	)

	colWidgets = append(colWidgets, cols)
	buttonRow := columns.NewWithDim(gowid.RenderWithWeight{W: 1}, colWidgets...)

	pileWidgets = append(pileWidgets, divider.NewBlank(), buttonRow)

	mainw = pile.NewFlow(pileWidgets...)

	var editColsDialog *dialog.Widget

	okButton := dialog.Button{
		Msg: "Ok",
		Action: gowid.WidgetChangedFunction(func(app gowid.IApp, widget gowid.IWidget) {
			newcols := pcols.ToConfigList()
			curcols := termshark.ConfStringSlice("main.column-format", []string{})

			if !reflect.DeepEqual(newcols, curcols) {
				termshark.SetConf("main.column-format-bak", curcols)
				termshark.SetConf("main.column-format", pcols.ToConfigList())
			} else {
				OpenMessage("No change - same columns configured", appView, app)
			}

			editColsDialog.Close(app)

			RequestReload(app)
		}),
	}

	editColsDialog = dialog.New(
		framed.NewSpace(
			mainw,
		),
		dialog.Options{
			Buttons:         []dialog.Button{okButton, dialog.Cancel},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	editColsDialog.Open(appView, ratio(0.5), app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
