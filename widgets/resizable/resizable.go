// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package resizable provides columns and piles that can be adjusted.
package resizable

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/pile"
)

//======================================================================

type Offset struct {
	Col1   int `json:"col1"`
	Col2   int `json:"col2"`
	Adjust int `json:"adjust"`
}

type IOffsets interface {
	GetOffsets() []Offset
	SetOffsets([]Offset, gowid.IApp)
}

type OffsetsCB struct{}

type ColumnsWidget struct {
	*columns.Widget
	Offsets   []Offset
	Callbacks *gowid.Callbacks
}

var _ IOffsets = (*ColumnsWidget)(nil)

func NewColumns(widgets []gowid.IContainerWidget) *ColumnsWidget {
	res := &ColumnsWidget{
		Widget:  columns.New(widgets),
		Offsets: make([]Offset, 0, 2),
	}
	return res
}

func (w *ColumnsWidget) GetOffsets() []Offset {
	return w.Offsets
}

func (w *ColumnsWidget) SetOffsets(offs []Offset, app gowid.IApp) {
	w.Offsets = offs
	gowid.RunWidgetCallbacks(w.Callbacks, OffsetsCB{}, app, w)
}

func (w *ColumnsWidget) OnOffsetsSet(cb gowid.IWidgetChangedCallback) {
	if w.Callbacks == nil {
		w.Callbacks = gowid.NewCallbacks()
	}
	gowid.AddWidgetCallback(w.Callbacks, OffsetsCB{}, cb)
}

func (w *ColumnsWidget) RemoveOnOffsetsSet(cb gowid.IIdentity) {
	if w.Callbacks == nil {
		w.Callbacks = gowid.NewCallbacks()
	}
	gowid.RemoveWidgetCallback(w.Callbacks, OffsetsCB{}, cb)
}

type AdjustFn func(x int) int

var Add1 AdjustFn = func(x int) int {
	return x + 1
}

var Subtract1 AdjustFn = func(x int) int {
	return x - 1
}

func (w *ColumnsWidget) AdjustOffset(col1 int, col2 int, fn AdjustFn, app gowid.IApp) {
	AdjustOffset(w, col1, col2, fn, app)
	gowid.RunWidgetCallbacks(w.Callbacks, OffsetsCB{}, app, w)
}

func AdjustOffset(w IOffsets, col1 int, col2 int, fn AdjustFn, app gowid.IApp) {
	idx := -1
	var off Offset
	for i, o := range w.GetOffsets() {
		if o.Col1 == col1 && o.Col2 == col2 {
			idx = i
			break
		}
	}
	if idx == -1 {
		off.Col1 = col1
		off.Col2 = col2
		w.SetOffsets(append(w.GetOffsets(), off), app)
		idx = len(w.GetOffsets()) - 1
	}
	w.GetOffsets()[idx].Adjust = fn(w.GetOffsets()[idx].Adjust)
}

func (w *ColumnsWidget) WidgetWidths(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp) []int {
	widths := w.Widget.WidgetWidths(size, focus, focusIdx, app)
	for _, off := range w.Offsets {
		addme := off.Adjust
		if widths[off.Col1]+addme < 0 {
			addme = -widths[off.Col1]
		} else if widths[off.Col2]-addme < 0 {
			addme = widths[off.Col2]
		}
		widths[off.Col1] += addme
		widths[off.Col2] -= addme
	}
	return widths
}

func (w *ColumnsWidget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	return columns.Render(w, size, focus, app)
}

func (w *ColumnsWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return columns.UserInput(w, ev, size, focus, app)
}

func (w *ColumnsWidget) RenderSubWidgets(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp) []gowid.ICanvas {
	return columns.RenderSubWidgets(w, size, focus, focusIdx, app)
}

func (w *ColumnsWidget) RenderedSubWidgetsSizes(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp) []gowid.IRenderBox {
	return columns.RenderedSubWidgetsSizes(w, size, focus, focusIdx, app)
}

func (w *ColumnsWidget) SubWidgetSize(size gowid.IRenderSize, newX int, sub gowid.IWidget, dim gowid.IWidgetDimension) gowid.IRenderSize {
	return w.Widget.SubWidgetSize(size, newX, sub, dim)
}

//======================================================================

type PileWidget struct {
	*pile.Widget
	Offsets   []Offset
	Callbacks *gowid.Callbacks
}

func NewPile(widgets []gowid.IContainerWidget) *PileWidget {
	res := &PileWidget{
		Widget:    pile.New(widgets),
		Offsets:   make([]Offset, 0, 2),
		Callbacks: gowid.NewCallbacks(),
	}
	return res
}

var _ IOffsets = (*ColumnsWidget)(nil)

func (w *PileWidget) GetOffsets() []Offset {
	return w.Offsets
}

func (w *PileWidget) SetOffsets(offs []Offset, app gowid.IApp) {
	w.Offsets = offs
	gowid.RunWidgetCallbacks(w.Callbacks, OffsetsCB{}, app, w)
}

func (w *PileWidget) OnOffsetsSet(cb gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w.Callbacks, OffsetsCB{}, cb)
}

func (w *PileWidget) RemoveOnOffsetsSet(cb gowid.IIdentity) {
	gowid.RemoveWidgetCallback(w.Callbacks, OffsetsCB{}, cb)
}

func (w *PileWidget) AdjustOffset(col1 int, col2 int, fn AdjustFn, app gowid.IApp) {
	AdjustOffset(w, col1, col2, fn, app)
	gowid.RunWidgetCallbacks(w.Callbacks, OffsetsCB{}, app, w)
}

type PileAdjuster struct {
	widget    *PileWidget
	origSizer pile.IPileBoxMaker
}

func (f PileAdjuster) MakeBox(w gowid.IWidget, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	adjustedSize := size
	var box gowid.RenderBox
	isbox := false
	switch size := size.(type) {
	case gowid.IRenderBox:
		box.C = size.BoxColumns()
		box.R = size.BoxRows()
		isbox = true
	}
	i := 0
	for ; i < len(f.widget.SubWidgets()); i++ {
		if w == f.widget.SubWidgets()[i] {
			break
		}
	}
	if i == len(f.widget.SubWidgets()) {
		panic("Unexpected pile state!")
	}
	if isbox {
		for _, off := range f.widget.Offsets {
			if i == off.Col1 {
				if box.R+off.Adjust < 0 {
					off.Adjust = -box.R
				}
				box.R += off.Adjust
			} else if i == off.Col2 {
				if box.R-off.Adjust < 0 {
					off.Adjust = box.R
				}
				box.R -= off.Adjust
			}
		}
		adjustedSize = box
	}
	return f.origSizer.MakeBox(w, adjustedSize, focus, app)
}

func (w *PileWidget) FindNextSelectable(dir gowid.Direction, wrap bool) (int, bool) {
	return gowid.FindNextSelectableFrom(w, w.Focus(), dir, wrap)
}

func (w *PileWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return pile.UserInput(w, ev, size, focus, app)
}

func (w *PileWidget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	return pile.Render(w, size, focus, app)
}

func (w *PileWidget) RenderedSubWidgetsSizes(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp) []gowid.IRenderBox {
	res, _ := pile.RenderedChildrenSizes(w, size, focus, focusIdx, app)
	return res
}

func (w *PileWidget) RenderSubWidgets(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp) []gowid.ICanvas {
	return pile.RenderSubwidgets(w, size, focus, focusIdx, app)
}

func (w *PileWidget) RenderBoxMaker(size gowid.IRenderSize, focus gowid.Selector, focusIdx int, app gowid.IApp, sizer pile.IPileBoxMaker) ([]gowid.IRenderBox, []gowid.IRenderSize) {
	x := &PileAdjuster{
		widget:    w,
		origSizer: sizer,
	}
	return pile.RenderBoxMaker(w, size, focus, focusIdx, app, x)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
