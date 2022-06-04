// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package copymodetable provides a wrapper around a table that supports copy mode.
// The implementation currently supports clipping a whole row and also the whole
// table by providing these as interfaces to the New function. It's easy to imagine
// supporting narrowing the copy selection to a single column, but I don't need
// that yet...
package copymodetable

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
	lru "github.com/hashicorp/golang-lru"
)

//======================================================================

type IRowCopier interface {
	CopyRow(id table.RowId) []gowid.ICopyResult
}

type ITableCopier interface {
	CopyTable() []gowid.ICopyResult
}

type ICopyModeTableNeeds interface {
	gowid.IWidget
	list.IWalker
	table.IGoToMiddle
	withscrollbar.IScrollOneLine
	withscrollbar.IScrollOnePage
	CurrentRow() int
	SetCurrentRow(table.Position)
	Model() table.IModel
	SetModel(table.IModel, gowid.IApp)
	Cache() *lru.Cache
	OnFocusChanged(gowid.IWidgetChangedCallback)
}

type Widget struct {
	ICopyModeTableNeeds
	RowClip IRowCopier               // Knows how to make a clip result set given a row
	AllClip ITableCopier             // Knows how to make a clip result set from the whole table
	name    string                   // for widget "id"
	clip    gowid.IClipboardSelected // function to modify selected widget for copying
}

type idstring string

// Needed to satisfy copy mode
func (i idstring) ID() interface{} {
	return i
}

func New(wrapped ICopyModeTableNeeds, rowClip IRowCopier, allClip ITableCopier, name string, clip gowid.IClipboardSelected) *Widget {
	return &Widget{
		ICopyModeTableNeeds: wrapped,
		RowClip:             rowClip,
		AllClip:             allClip,
		name:                name,
		clip:                clip,
	}
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if app.InCopyMode() && app.CopyModeClaimedBy().ID() == w.ID() && focus.Focus {
		row := w.CurrentRow()
		if app.CopyModeClaimedAt() == 0 {
			row = -1 // all rows
		}

		origModel := w.Model()

		model := copyModeTableModel{
			IModel: origModel,
			clip:   w.clip,
			app:    app,
			row:    row,
		}

		w.SetModel(model, app)
		res := w.ICopyModeTableNeeds.Render(size, focus, app)
		w.SetModel(origModel, app)

		return res
	} else {
		return w.ICopyModeTableNeeds.Render(size, focus, app)
	}
}

// The app stores which widget claims copy mode, and so each widget must check whether it's the
// one when it render itself.
func (w *Widget) ID() interface{} {
	return idstring(w.name)
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.ICopyModeTableNeeds
}

func (w *Widget) CopyModeLevels() int {
	return 1 // one row, all rows
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return gowid.CopyModeUserInput(w, ev, size, focus, app)
}

func (w *Widget) Clips(app gowid.IApp) []gowid.ICopyResult {
	// 1 is whole table
	// 0 is just row
	diff := w.CopyModeLevels() - (app.CopyModeClaimedAt() - app.CopyLevel())

	var rd []gowid.ICopyResult
	if diff == 0 {
		cur := w.CurrentRow()
		rid, ok := w.Model().RowIdentifier(cur)
		if ok {
			rd = w.RowClip.CopyRow(rid)
		}
	} else {
		rd = w.AllClip.CopyTable()
	}

	return rd
}

//======================================================================

// copyModeTableModel exists solely to provide an "overridden" implementation of CellWidgets e.g. to color the
// selected row yellow. To do this, it needs clip for the AlterWidget function, and the row to alter (or
// all). This model is set on the underlying table before Render() is called on the underlying table.
type copyModeTableModel struct {
	table.IModel
	clip gowid.IClipboardSelected
	app  gowid.IApp
	row  int
}

var _ table.IModel = copyModeTableModel{}

func (c copyModeTableModel) CellWidgets(row table.RowId) []gowid.IWidget {
	res := c.IModel.CellWidgets(row)
	dothisrow := false
	if c.row == -1 {
		dothisrow = true // do every row i.e. every call to CellWidgets()
	} else {
		rid, ok := c.IModel.RowIdentifier(c.row)
		if ok && (row == rid) {
			dothisrow = true
		}
	}
	if dothisrow {
		for col := 0; col < len(res); col++ {
			res[col] = c.clip.AlterWidget(res[col], c.app)
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
