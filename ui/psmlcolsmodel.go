// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/gowid/widgets/vpadding"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/gcla/termshark/v2/pkg/shark/wiresharkcfg"
	"github.com/gcla/termshark/v2/widgets/filter"
	"github.com/gcla/termshark/v2/widgets/number"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var ColumnsFormatError = fmt.Errorf("The supplied list of columns and names is invalid")

var filler *fill.Widget

// psmlColumnsModel is itself a gowid table widget. This allows me to use the model
// directly in the widget hierarchy, and has the advantage that if I update the model,
// I can regenerate the embedded table widget because I have a handle to it. Otherwise
// I would need to build a more complicated model with callbacks when data changes, and
// have those callbacks tied to the table displaying the data.

type psmlDialogWidgets struct {
	customName   *edit.Widget // save the user-configured name
	customFilter *filter.Widget
	occurrence   *number.Widget
	visible      *checkbox.Widget // save the visible selections
}

type psmlColumnsModel struct {
	spec       []shark.PsmlColumnSpec // the actual rows - field name, long name
	widgets    []psmlDialogWidgets
	haveCustom bool
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

func init() {
	filler = fill.New(' ')
}

func NewDefaultPsmlColumnsModel(app gowid.IApp) *psmlColumnsModel {
	spec := shark.DefaultPsmlColumnSpec
	// copy it to protect from alterations
	specCopy := make([]shark.PsmlColumnSpec, len(spec))
	for i := 0; i < len(spec); i++ {
		specCopy[i] = spec[i]
	}
	res := &psmlColumnsModel{
		spec: specCopy,
	}
	res.fixup(app)
	return res
}

func NewPsmlColumnsModel(app gowid.IApp) *psmlColumnsModel {
	spec := shark.GetPsmlColumnFormat()
	res := &psmlColumnsModel{
		spec: spec,
	}
	res.fixup(app)
	return res
}

func NewPsmlColumnsModelFrom(colsKey string, app gowid.IApp) *psmlColumnsModel {
	spec := shark.GetPsmlColumnFormatFrom(colsKey)
	res := &psmlColumnsModel{
		spec: spec,
	}
	res.fixup(app)
	return res
}

//======================================================================

func (p *psmlColumnsModel) Close() error {
	var err error
	for i := 0; i < len(p.widgets); i++ {
		if p.widgets[i].customFilter != nil {
			err2 := p.widgets[i].customFilter.Close()
			if err == nil {
				err = err2
			}
		}
	}
	return err
}

func (p *psmlColumnsModel) String() string {
	return fmt.Sprintf("%v", p.spec)
}

func (p *psmlColumnsModel) FieldToString(i int) string {
	field := p.spec[i].Field.Token
	if field == "%Cus" {
		field = fmt.Sprintf("%s:%s:%d:R",
			field,
			p.widgets[i].customFilter.Value(),
			p.widgets[i].occurrence.Value,
		)
	}
	return field
}

// ToConfigList converts the information in the current PSML columns model to
// a slice of strings suitable for writing to the termshark toml file.
func (p *psmlColumnsModel) ToConfigList() []string {
	res := make([]string, 0, len(p.spec))
	for i := 0; i < len(p.spec); i++ {
		res = append(res, p.FieldToString(i))
		res = append(res, p.widgets[i].customName.Text())
		res = append(res, fmt.Sprintf("%v", p.widgets[i].visible.IsChecked()))
	}
	return res
}

type specToWidgets shark.PsmlColumnSpec

func (sp *specToWidgets) widgets() psmlDialogWidgets {
	return psmlDialogWidgets{
		customName: edit.New(edit.Options{
			Text: sp.Name,
		}),
		customFilter: filter.New("psmlfilter", filter.Options{
			Completer:  savedCompleter{def: FieldCompleter},
			MenuOpener: &multiMenu1Opener,
			Position:   filter.Below,
		}),
		visible: checkbox.New(!sp.Hidden),
		occurrence: number.New(number.Options{
			Value: sp.Field.Occurrence,
			Min:   gwutil.SomeInt(0),
			Styler: func(w gowid.IWidget) gowid.IWidget {
				return styled.NewInvertedFocus(w, gowid.MakePaletteRef("dialog"))
			},
		}),
	}
}

func (p *psmlColumnsModel) AddRow() {
	p.spec = append(p.spec, shark.PsmlColumnSpec{Field: shark.PsmlField{Token: "%m"}, Name: "No."})

	sp := specToWidgets(p.spec[len(p.spec)-1])
	w := sp.widgets()
	p.widgets = append(p.widgets, w)

	if sp.Field.Token == "%Cus" {
		p.haveCustom = true
	}

	p.Widget = table.New(p)
}

// cacheHaveCustom keeps track of whether the current model has any custom columns. This
// is done each time the model is updated. If custom columns are present, the table is
// displayed with two extra columns.
func (p *psmlColumnsModel) cacheHaveCustom() {
	for _, w := range p.spec {
		if w.Field.Token == "%Cus" {
			p.haveCustom = true
			return
		}
	}
	p.haveCustom = false
}

// Make rest of data structure consistent with recent changes
func (p *psmlColumnsModel) fixup(app gowid.IApp) {
	p.haveCustom = false
	p.widgets = make([]psmlDialogWidgets, 0)
	for i := 0; i < len(p.spec); i++ {
		sp := specToWidgets(p.spec[i])
		w := sp.widgets()

		if p.spec[i].Field.Token == "%Cus" {
			p.haveCustom = true
			w.customFilter.SetValue(p.spec[i].Field.Filter, app)
		}

		p.widgets = append(p.widgets, w)
	}

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

func (p *psmlColumnsModel) ReadFromWireshark(app gowid.IApp) error {
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
		var field shark.PsmlField
		err := field.FromString(stripQuotes(wcols[i+1]))
		if err != nil {
			return err
		}
		specs = append(specs, shark.PsmlColumnSpec{
			Field: field,
			Name:  stripQuotes(wcols[i]),
		})
	}

	p.spec = specs
	p.fixup(app)
	return nil
}

// Called when user chooses from a menu - so will only have PsmlField Token name
func (p *psmlColumnsModel) UpdateFromField(field string, idx int, app gowid.IApp) {
	if p.spec[idx].Field.Token == "%Cus" && field != "%Cus" {
		err := p.widgets[idx].customFilter.Close()
		if err != nil {
			log.Warnf("Unexpected response when closing filter: %v", err)
		}
	}

	p.spec[idx].Field.Token = field
	p.spec[idx].Name = shark.AllowedColumnFormats[field].Long

	p.cacheHaveCustom()

	p.Widget = table.New(p)
}

func (m *psmlColumnsModel) moveDown(row int, app gowid.IApp) {
	i := row
	j := row + 1

	m.spec[i], m.spec[j] = m.spec[j], m.spec[i]
	m.widgets[i], m.widgets[j] = m.widgets[j], m.widgets[i]

	m.Widget = table.New(m)
}

func (m *psmlColumnsModel) moveUp(row int, app gowid.IApp) {
	i := row
	j := row - 1

	m.spec[i], m.spec[j] = m.spec[j], m.spec[i]
	m.widgets[i], m.widgets[j] = m.widgets[j], m.widgets[i]

	m.Widget = table.New(m)
}

// row is the screen position
func (m *psmlColumnsModel) deleteRow(trow table.RowId, app gowid.IApp) {
	row := int(trow)

	// Do this to close the filter goroutines
	err := m.widgets[row].customFilter.Close()
	if err != nil {
		log.Warnf("Unexpected response when closing filter: %v", err)
	}

	m.spec = append(m.spec[:row], m.spec[row+1:]...)
	m.widgets = append(m.widgets[:row], m.widgets[row+1:]...)

	m.cacheHaveCustom()

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
			fixed,
		)
	}

	colsMenuFieldsSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	// Field name
	colsMenuFieldsButton := button.NewBare(text.New(p.spec[rowi].Field.Token))
	colsMenuFieldsButton.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		wid, hei := rebuildPsmlFieldListBox(app)
		colsCurrentModelRow = rowi
		colFieldsMenu.SetWidth(units(wid), app)
		colFieldsMenu.SetHeight(units(hei), app)
		multiMenu1Opener.OpenMenu(colFieldsMenu, colsMenuFieldsSite, app)
	}))

	// "^"
	if rowi == 0 {
		res = append(res, nullw)
	} else {
		res = append(res, pad(text.New("^"), left, rowi, func(r int) gowid.WidgetChangedFunction {
			return func(app gowid.IApp, target gowid.IWidget) {
				p.moveUp(r, app)
			}
		}))
	}

	// "v"
	if rowi == len(p.spec)-1 {
		res = append(res, nullw)
	} else {
		res = append(res, pad(text.New("v"), left, rowi, func(r int) gowid.WidgetChangedFunction {
			return func(app gowid.IApp, target gowid.IWidget) {
				p.moveDown(r, app)
			}
		}))
	}

	// "[X]"
	res = append(res, hpadding.New(
		clicktracker.New(
			styled.NewExt(
				p.widgets[row].visible,
				gowid.MakePaletteRef("dialog"),
				gowid.MakePaletteRef("dialog-button"),
			),
		),
		left,
		fixed,
	))

	// %Yut prep
	fcols := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: colsMenuFieldsSite,
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: clicktracker.New(
				styled.NewExt(
					colsMenuFieldsButton,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
			),
			D: fixed,
		},
	})

	// %Yut
	res = append(res, fcols)

	// Filter
	if p.haveCustom {
		if p.spec[row].Field.Token == "%Cus" {
			res = append(res, p.widgets[row].customFilter)
			res = append(res, hpadding.New(p.widgets[row].occurrence, mid, fixed))
		} else {
			res = append(res, nullw)
			res = append(res, nullw)
		}
	}

	// "gcla1"
	res = append(res, p.widgets[row].customName)

	colsMenuSite := menu.NewSite(menu.SiteOptions{YOffset: 1})
	colsMenuButton := button.NewBare(text.New(shark.AllowedColumnFormats[p.spec[row].Field.Token].Long))
	colsMenuButton.OnClick(gowid.MakeWidgetCallback(gowid.ClickCB{}, func(app gowid.IApp, target gowid.IWidget) {
		wid, hei := rebuildPsmlNamesListBox(p, app)
		colsCurrentModelRow = rowi
		colNamesMenu.SetWidth(units(wid), app)
		colNamesMenu.SetHeight(units(hei), app)
		multiMenu1Opener.OpenMenu(colNamesMenu, colsMenuSite, app)
	}))

	//
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

	// "X"
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
	if !p.haveCustom {
		return 7
	} else {
		return 7 + 2
	}
}

func (p *psmlColumnsModel) Widths() []gowid.IWidgetDimension {
	if !p.haveCustom {
		return []gowid.IWidgetDimension{
			gowid.RenderWithUnits{U: 3},
			gowid.RenderWithUnits{U: 4},
			gowid.RenderWithWeight{W: 1},
			gowid.RenderWithWeight{W: 1},
			gowid.RenderWithWeight{W: 2},
			gowid.RenderWithWeight{W: 3},
			gowid.RenderWithUnits{U: 9},
		}
	} else {
		return []gowid.IWidgetDimension{
			gowid.RenderWithUnits{U: 3},
			gowid.RenderWithUnits{U: 4},
			gowid.RenderWithWeight{W: 1},
			gowid.RenderWithWeight{W: 1},
			//
			gowid.RenderWithWeight{W: 4},
			gowid.RenderWithUnits{U: 8},
			//
			gowid.RenderWithWeight{W: 2},
			gowid.RenderWithWeight{W: 3},
			gowid.RenderWithUnits{U: 9},
		}
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
		return vpadding.New(
			styled.NewExt(w, gowid.ColorInverter{pr}, gowid.ColorInverter{pr}),
			gowid.VAlignTop{},
			gowid.RenderWithUnits{U: 1},
		)
	}

	if !p.haveCustom {
		return []gowid.IWidget{
			st(text.New("")),
			st(text.New("")),
			st(text.New("Show")),
			st(text.New("Field")),
			st(text.New("Your Name")),
			st(text.New("Official")),
			st(text.New("Remove")),
		}
	} else {
		return []gowid.IWidget{
			st(text.New("")),
			st(text.New("")),
			st(text.New("Show")),
			st(text.New("Field")),
			//
			st(text.New("Filter")),
			st(text.New("#Occ")),
			//
			st(text.New("Your Name")),
			st(text.New("Official")),
			st(text.New("Remove")),
		}
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
