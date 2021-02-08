// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/shark"
	"github.com/gcla/termshark/v2/shark/wiresharkcfg"
)

//======================================================================

var ColumnsFormatError = fmt.Errorf("The supplied list of columns and names is invalid")

// psmlColumnsModel is itself a gowid table widget. This allows me to use the model
// directly in the widget hierarchy, and has the advantage that if I update the model,
// I can regenerate the embedded table widget because I have a handle to it. Otherwise
// I would need to build a more complicated model with callbacks when data changes, and
// have those callbacks tied to the table displaying the data.
type psmlColumnsModel struct {
	spec        []shark.PsmlColumnSpec // the actual rows - field name, long name
	customNames []*edit.Widget         // save the user-configured name
	*table.Widget
}

var _ table.IBoundedModel = (*psmlColumnsModel)(nil)
var _ table.IInvertible = (*psmlColumnsModel)(nil)

var (
	left  = gowid.HAlignLeft{}
	mid   = gowid.HAlignMiddle{}
	right = gowid.HAlignRight{}
)

//======================================================================

func NewDefaultPsmlColumnsModel() *psmlColumnsModel {
	spec := shark.DefaultPsmlColumnSpec
	// copy it to protect from alterations
	specCopy := make([]shark.PsmlColumnSpec, len(spec))
	for i := 0; i < len(spec); i++ {
		specCopy[i] = spec[i]
	}
	res := &psmlColumnsModel{
		spec: specCopy,
	}
	res.fixup()
	return res
}

func NewPsmlColumnsModel() *psmlColumnsModel {
	spec := shark.GetPsmlColumnFormat()
	res := &psmlColumnsModel{
		spec: spec,
	}
	res.fixup()
	return res
}

func NewPsmlColumnsModelFrom(key string) *psmlColumnsModel {
	spec := shark.GetPsmlColumnFormatFrom(key)
	res := &psmlColumnsModel{
		spec: spec,
	}
	res.fixup()
	return res
}

func (p *psmlColumnsModel) String() string {
	return fmt.Sprintf("%v", p.spec)
}

func (p *psmlColumnsModel) ToConfigList() []string {
	res := make([]string, 0, len(p.spec))
	for i := 0; i < len(p.spec); i++ {
		custom := p.customNames[i].Text()
		if custom == "" {
			res = append(res, p.spec[i].Field)
		} else {
			res = append(res, fmt.Sprintf("%s %s", p.spec[i].Field, custom))
		}
	}
	return res
}

func (p *psmlColumnsModel) AddRow() {
	p.spec = append(p.spec, shark.PsmlColumnSpec{Field: "%m", Name: "No."})
	p.customNames = append(p.customNames, edit.New(edit.Options{
		Text: p.spec[len(p.spec)-1].Name,
	}))
}

// Make rest of data structure consistent with recent changes
func (p *psmlColumnsModel) fixup() {
	cnames := make([]*edit.Widget, len(p.spec))
	for i := 0; i < len(cnames); i++ {
		cnames[i] = edit.New(edit.Options{
			Text: p.spec[i].Name,
		})
	}
	p.customNames = cnames
	p.Widget = table.New(p)
}

func stripQuotes(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func (p *psmlColumnsModel) ReadFromWireshark() error {
	wcfg, err := wiresharkcfg.NewDefault()
	if err != nil {
		return err
	}

	wcols := wcfg.ColumnFormat()
	if wcols == nil {
		return fmt.Errorf("Could not read Wireshark column preferences")
	}

	if (len(wcols)/2)*2 != len(wcols) {
		return gowid.WithKVs(ColumnsFormatError, map[string]interface{}{
			"columns": wcols,
		})
	}

	specs := make([]shark.PsmlColumnSpec, 0)
	for i := 0; i < len(wcols); i += 2 {
		specs = append(specs, shark.PsmlColumnSpec{
			Field: stripQuotes(wcols[i+1]),
			Name:  stripQuotes(wcols[i]),
		})
	}

	p.spec = specs
	p.fixup()
	return nil
}

func (p *psmlColumnsModel) UpdateFromField(field string, idx int) {
	p.spec[idx].Field = field
	p.spec[idx].Name = shark.AllowedColumnFormats[field].Long

	p.Widget = table.New(p)
}

func (p *psmlColumnsModel) UpdateFromField2(field string, idx int) {
	p.spec[idx].Field = field
	p.spec[idx].Name = shark.AllowedColumnFormats[field].Long

	p.Widget = table.New(p)
}

// WriteToConfig writes the PSML column model to the termshark toml
func (m *psmlColumnsModel) WriteToConfig() {
	tcols := make([]string, 0)
	for _, v := range m.spec {
		tcols = append(tcols, fmt.Sprintf("%s %s", v.Field, v.Name))
	}
	termshark.SetConf("main.column-format", tcols)
}

func (m *psmlColumnsModel) moveDown(row int, app gowid.IApp) {
	i := row
	j := row + 1

	m.spec[i], m.spec[j] = m.spec[j], m.spec[i]
	m.customNames[i], m.customNames[j] = m.customNames[j], m.customNames[i]

	m.Widget = table.New(m)
}

func (m *psmlColumnsModel) moveUp(row int, app gowid.IApp) {
	i := row
	j := row - 1

	m.spec[i], m.spec[j] = m.spec[j], m.spec[i]
	m.customNames[i], m.customNames[j] = m.customNames[j], m.customNames[i]

	m.Widget = table.New(m)
}

// row is the screen position
func (m *psmlColumnsModel) deleteRow(trow table.RowId, app gowid.IApp) {
	row := int(trow)
	m.spec = append(m.spec[:row], m.spec[row+1:]...)
	m.customNames = append(m.customNames[:row], m.customNames[row+1:]...)

	m.Widget = table.New(m)
}

// construct the widgets for each row in the dialog used to configure PSML
// columns.
func (p *psmlColumnsModel) CellWidgets(row table.RowId) []gowid.IWidget {
	rowi := int(row)

	res := make([]gowid.IWidget, 0)

	pad := func(w gowid.IWidget, pos gowid.IHAlignment, r int, fn func(int) gowid.WidgetChangedFunction) gowid.IWidget {
		btn := button.NewAlt(w)
		btn.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, fn(r)))

		return hpadding.New(
			clicktracker.New(
				styled.NewExt(
					btn,
					gowid.MakePaletteRef("dialog"),
					gowid.MakePaletteRef("dialog-button"),
				),
			),
			pos,
			gowid.RenderFixed{},
		)
	}

	colsMenuFieldsSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	// Field name
	colsMenuFieldsButton := button.NewBare(text.New(p.spec[rowi].Field))
	colsMenuFieldsButton.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		wid, hei := rebuildPsmlFieldListBox(app)
		colsCurrentModelRow = rowi
		colFieldsMenu.SetWidth(units(wid), app)
		colFieldsMenu.SetHeight(units(hei), app)
		colFieldsMenu.Open(colsMenuFieldsSite, app)
	}))

	if rowi == 0 {
		res = append(res, nullw)
	} else {
		res = append(res, pad(text.New("^"), left, rowi, func(r int) gowid.WidgetChangedFunction {
			return func(app gowid.IApp, target gowid.IWidget) {
				p.moveUp(r, app)
			}
		}))
	}

	if rowi == len(p.spec)-1 {
		res = append(res, nullw)
	} else {
		res = append(res, pad(text.New("v"), left, rowi, func(r int) gowid.WidgetChangedFunction {
			return func(app gowid.IApp, target gowid.IWidget) {
				p.moveDown(r, app)
			}
		}))
	}
	res = append(res,
		columns.NewFixed(
			colsMenuFieldsSite,
			clicktracker.New(
				styled.NewExt(
					colsMenuFieldsButton,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
			),
		),
	)
	res = append(res, p.customNames[row])

	colsMenuSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	colsMenuButton := button.NewBare(text.New(shark.AllowedColumnFormats[p.spec[row].Field].Long))
	colsMenuButton.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		wid, hei := rebuildPsmlNamesListBox(p, app)
		colsCurrentModelRow = rowi
		colNamesMenu.SetWidth(units(wid), app)
		colNamesMenu.SetHeight(units(hei), app)
		colNamesMenu.Open(colsMenuSite, app)
	}))

	res = append(res,
		columns.NewFixed(
			colsMenuSite,
			clicktracker.New(
				styled.NewExt(
					colsMenuButton,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
			),
		),
	)

	if len(p.spec) <= 1 {
		res = append(res, nullw)
	} else {
		res = append(res, pad(text.New("X"), mid, rowi, func(r int) gowid.WidgetChangedFunction {
			return func(app gowid.IApp, target gowid.IWidget) {
				p.deleteRow(row, app)
			}
		}))
	}

	return res
}

func (p *psmlColumnsModel) Columns() int {
	return 6
}

func (p *psmlColumnsModel) Widths() []gowid.IWidgetDimension {
	return []gowid.IWidgetDimension{
		gowid.RenderWithUnits{U: 3},
		gowid.RenderWithUnits{U: 4},
		gowid.RenderWithWeight{W: 1},
		gowid.RenderWithWeight{W: 1},
		gowid.RenderWithWeight{W: 1},
		gowid.RenderWithUnits{U: 9},
	}
}

func (p *psmlColumnsModel) Rows() int {
	return len(p.spec)
}

func (p *psmlColumnsModel) HorizontalSeparator() gowid.IWidget {
	return nil
}

func (p *psmlColumnsModel) HeaderSeparator() gowid.IWidget {
	return nil
}

func (p *psmlColumnsModel) HeaderWidgets() []gowid.IWidget {

	pr := gowid.MakePaletteRef("dialog")
	st := func(w gowid.IWidget) gowid.IWidget {
		return styled.NewExt(w, gowid.ColorInverter{pr}, gowid.ColorInverter{pr})
	}

	return []gowid.IWidget{
		st(text.New("")),
		st(text.New(" ")),
		st(text.New("  Field ")),
		st(text.New("  Custom ")),
		st(text.New("  Name ")),
		st(text.New("  Remove ")),
	}
}

func (p *psmlColumnsModel) VerticalSeparator() gowid.IWidget {
	return nil
}

func (p *psmlColumnsModel) RowIdentifier(row int) (table.RowId, bool) {
	if row < 0 || row >= len(p.spec) {
		return -1, false
	}
	return table.RowId(row), true
}

func (p *psmlColumnsModel) IdentifierToRow(rowid table.RowId) (int, bool) {
	if rowid < 0 || int(rowid) >= len(p.spec) {
		return -1, false
	} else {
		return int(rowid), true
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
