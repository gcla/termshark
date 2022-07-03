// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package scrollabletable makes a widget that some scrollbar interfaces
// suitable for passing to withscrollbar.New()
package scrollabletable

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
)

//======================================================================

type IScrollableTable interface {
	gowid.IWidget
	withscrollbar.IScrollOneLine
	withscrollbar.IScrollOnePage
	CurrentRow() int
	Model() table.IModel
}

// To implement withscrollbar.IScrollValues
type Widget struct {
	IScrollableTable
}

// makes a IScrollableTable suitable for passing to withscrollbar.New()
var _ withscrollbar.IScrollSubWidget = Widget{}
var _ withscrollbar.IScrollSubWidget = (*Widget)(nil)

func New(t IScrollableTable) *Widget {
	return &Widget{
		IScrollableTable: t,
	}
}

func (s Widget) ScrollLength() int {
	return s.Model().(table.IBoundedModel).Rows()
}

func (s Widget) ScrollPosition() int {
	return s.CurrentRow()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
