// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
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
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/pkg/shark/wiresharkcfg"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gdamore/tcell/v2"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var colNamesMenu *menu.Widget
var colFieldsMenu *menu.Widget

// These are global variables used to hold the current model for the edit-columns
// widget, and the current line selected. This is hacky but it's so that I can tell,
// when a menu button is clicked within this PSML columns widget, which column
// it should apply to. I could generate unique menus for each row of the table, as
// an alternative...
var CurrentColsWidget *psmlColumnsModel
var colsCurrentModelRow int

var colNamesMenuListBoxHolder *holder.Widget
var colFieldsMenuListBoxHolder *holder.Widget

//======================================================================

// psmlColumnInfoArraySortLong allows for sorting an array of PsmlColumnInfo by the
// longer name - for use in the long-name drop down menu
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

//======================================================================

func buildNamesMenu(app gowid.IApp) {
	colNamesMenuListBoxHolder = holder.New(null.New())

	wid, hei := rebuildPsmlNamesListBox(CurrentColsWidget, app)

	colNamesMenu = menu.New("psmlcols", colNamesMenuListBoxHolder, gowid.RenderWithUnits{U: wid}, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		OpenCloser:        &multiMenu1Opener,
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
		OpenCloser:        &multiMenu1Opener,
		CloseKeys: []gowid.IKey{
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})
	colFieldsMenu.SetHeight(units(hei), app)
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
		specCopy := spec
		colsMenuItems = append(colsMenuItems,
			menuutil.SimpleMenuItem{
				Txt: spec.Long,
				CB: func(app gowid.IApp, w gowid.IWidget) {
					multiMenu1Opener.CloseMenu(colNamesMenu, app)
					p.UpdateFromField(specCopy.Field, colsCurrentModelRow, app)
				},
			},
		)
	}

	colsMenuListBox, wid := menuutil.MakeMenu(colsMenuItems, nil)
	colNamesMenuListBoxHolder.SetSubWidget(colsMenuListBox, nil)

	return wid, len(specs)
}

func rebuildPsmlFieldListBox(app gowid.IApp) (int, int) {
	p := CurrentColsWidget

	colsMenuItems := make([]menuutil.SimpleMenuItem, 0)

	columnNames := make([]string, 0)
	for k, _ := range shark.AllowedColumnFormats {
		columnNames = append(columnNames, k)
	}
	sort.Strings(columnNames)

	for _, cname := range columnNames {
		cnameCopy := cname
		colsMenuItems = append(colsMenuItems,
			menuutil.SimpleMenuItem{
				Txt: cname,
				CB: func(app gowid.IApp, w gowid.IWidget) {
					multiMenu1Opener.CloseMenu(colFieldsMenu, app)
					p.UpdateFromField(cnameCopy, colsCurrentModelRow, app)
				},
			},
		)
	}

	colsMenuListBox, wid := menuutil.MakeMenu(colsMenuItems, nil)
	colFieldsMenuListBoxHolder.SetSubWidget(colsMenuListBox, nil)

	return wid, len(columnNames)
}

//======================================================================

func openEditColumns(app gowid.IApp) {
	pcols := NewPsmlColumnsModel(app)
	CurrentColsWidget = pcols

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
				newPcols := NewPsmlColumnsModel(app)
				err = newPcols.ReadFromWireshark(app)
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

	bakCols := profiles.ConfStringSlice("main.column-format-bak", []string{})
	if len(bakCols) != 0 {
		btn := button.New(text.New("Restore"))
		btn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
			newPcols := NewPsmlColumnsModelFrom("main.column-format-bak", app)
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
		*pcols = *NewDefaultPsmlColumnsModel(app)
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
		Action: gowid.MakeWidgetCallback("cb",
			gowid.WidgetChangedFunction(func(app gowid.IApp, widget gowid.IWidget) {
				for i := 0; i < len(pcols.spec); i++ {
					if pcols.spec[i].Field.Token == "%Cus" && !pcols.widgets[i].customFilter.IsValid() {
						OpenMessage(fmt.Sprintf("Custom column %d is invalid", i+1), appView, app)
						return
					}
				}

				newcols := pcols.ToConfigList()
				curcols := profiles.ConfStringSlice("main.column-format", []string{})

				updated := false
				if !reflect.DeepEqual(newcols, curcols) {
					profiles.SetConf("main.column-format-bak", curcols)
					profiles.SetConf("main.column-format", newcols)
					updated = true
				}

				editColsDialog.Close(app)

				if !updated {
					OpenMessage("No change - same columns configured", appView, app)
				} else {
					RequestReload(app)
				}
			}),
		),
	}

	editColsDialog = dialog.New(
		framed.NewSpace(
			mainw,
		),
		dialog.Options{
			Buttons:         []dialog.Button{okButton, dialog.Cancel},
			Modal:           true,
			NoShadow:        true,
			TabToButtons:    true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	dialogOpen := false
	editColsDialog.OnOpenClose(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		dialogOpen = !dialogOpen
		if !dialogOpen {
			CurrentColsWidget = nil
			err := pcols.Close()
			if err != nil {
				log.Warnf("Unexpected result closing PSML columns dialog: %v", err)
			}

		}
	}))

	editColsDialog.Open(appView, ratio(0.7), app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
