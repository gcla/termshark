// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package psmlmodel

import (
	"sort"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2/widgets/expander"
)

//======================================================================

// Model is a table model that provides a widget that will render
// in one row only when not selected.
type Model struct {
	*table.SimpleModel
	styler gowid.ICellStyler
}

func New(m *table.SimpleModel, st gowid.ICellStyler) *Model {
	return &Model{
		SimpleModel: m,
		styler:      st,
	}
}

// Provides the ith "cell" widget, upstream makes the "row"
func (c *Model) CellWidget(i int, s string) gowid.IWidget {
	w := table.SimpleCellWidget(c, i, s)
	if w != nil {
		w = expander.New(w)
	}
	return w
}

func (c *Model) CellWidgets(row table.RowId) []gowid.IWidget {
	return table.SimpleCellWidgets(c, row)
}

// table.ITable2
func (c *Model) HeaderWidget(ws []gowid.IWidget, focus int) gowid.IWidget {
	hws := c.HeaderWidgets()
	hw := c.SimpleModel.HeaderWidget(hws, focus).(*columns.Widget)
	hw2 := isselected.NewExt(
		hw,
		styled.New(hw, c.styler),
		styled.New(hw, c.styler),
	)
	return hw2
}

func (c *Model) HeaderWidgets() []gowid.IWidget {
	var res []gowid.IWidget
	if c.Headers != nil {

		res = make([]gowid.IWidget, 0, len(c.Headers))
		bhs := make([]*holder.Widget, len(c.Headers))
		bms := make([]*button.Widget, len(c.Headers))
		for i, s := range c.Headers {
			i2 := i
			var all, label gowid.IWidget
			label = text.New(s + " ")

			sorters := c.Comparators
			if sorters != nil {
				sorteri := sorters[i2]
				if sorteri != nil {
					bmid := button.NewBare(text.New("-"))
					bfor := button.NewBare(text.New("^"))
					brev := button.NewBare(text.New("v"))
					bh := holder.New(bmid)
					bhs[i] = bh
					bms[i] = bmid

					action := func(rev bool, next *button.Widget, app gowid.IApp) {
						sorter := &table.SimpleTableByColumn{
							SimpleModel: c.SimpleModel,
							Column:      i2,
						}
						if rev {
							sort.Sort(sort.Reverse(sorter))
						} else {
							sort.Sort(sorter)
						}
						bh.SetSubWidget(next, app)
						for j, bhj := range bhs {
							if j != i2 {
								bhj.SetSubWidget(bms[j], app)
							}
						}
					}

					bmid.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
						action(false, bfor, app)
					}))

					bfor.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
						action(true, brev, app)
					}))

					brev.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
						action(false, bfor, app)
					}))

					all = columns.NewFixed(label, styled.NewFocus(bh, gowid.MakeStyledAs(gowid.StyleReverse)))
				}
			}
			var w gowid.IWidget
			if c.Style.HeaderStyleProvided {
				w = isselected.New(
					styled.New(
						all,
						c.GetStyle().HeaderStyleNoFocus,
					),
					styled.New(
						all,
						c.GetStyle().HeaderStyleSelected,
					),
					styled.New(
						all,
						c.GetStyle().HeaderStyleFocus,
					),
				)
			} else {
				w = styled.NewExt(
					all,
					nil,
					gowid.MakeStyledAs(gowid.StyleReverse),
				)
			}
			res = append(res, w)
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
