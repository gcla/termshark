// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package hexdumper provides a numeric widget with a couple of buttons that increase or decrease its value.
package number

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/fill"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/text"
)

//======================================================================

type Options struct {
	Value  int
	Max    gwutil.IntOption
	Min    gwutil.IntOption
	Styler func(gowid.IWidget) gowid.IWidget
}

type Widget struct {
	gowid.IWidget
	up        *button.Widget
	down      *button.Widget
	valHolder *holder.Widget
	Value     int
	Opt       Options
}

var _ gowid.IWidget = (*Widget)(nil)

var blank *hpadding.Widget
var upArrow *text.Widget
var downArrow *text.Widget
var leftbr *text.Widget
var rightbr *text.Widget

func init() {
	blank = hpadding.New(
		fill.New(' '),
		gowid.HAlignLeft{},
		gowid.RenderWithUnits{U: 1},
	)

	leftbr = text.New("[")
	rightbr = text.New("]")
	upArrow = text.New("^")
	downArrow = text.New("v")
}

func New(opts ...Options) *Widget {

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &Widget{
		valHolder: holder.New(text.New(fmt.Sprintf("%d", opt.Value))),
		Value:     opt.Value,
	}

	up := button.NewBare(upArrow)

	up.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		if !res.Opt.Max.IsNone() && res.Value >= res.Opt.Max.Val() {
			res.Value = res.Opt.Max.Val()
		} else {
			res.Value += 1
		}
		res.valHolder.SetSubWidget(text.New(fmt.Sprintf("%d", res.Value)), app)
	}))

	down := button.NewBare(downArrow)

	down.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
		if !res.Opt.Min.IsNone() && res.Value <= res.Opt.Min.Val() {
			res.Value = res.Opt.Min.Val()
		} else {
			res.Value -= 1
		}
		res.valHolder.SetSubWidget(text.New(fmt.Sprintf("%d", res.Value)), app)
	}))

	styler := opt.Styler
	if styler == nil {
		styler = func(w gowid.IWidget) gowid.IWidget {
			return w
		}
	}

	cols := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: res.valHolder,
			D:       gowid.RenderFixed{},
			//D:       gowid.RenderWithWeight{W: 1},
		},
		&gowid.ContainerWidget{
			IWidget: blank,
			D:       gowid.RenderWithUnits{U: 1},
		},
		&gowid.ContainerWidget{
			IWidget: leftbr,
			D:       gowid.RenderFixed{},
		},
		&gowid.ContainerWidget{
			IWidget: styler(up),
			D:       gowid.RenderFixed{},
		},
		&gowid.ContainerWidget{
			IWidget: styler(down),
			D:       gowid.RenderFixed{},
		},
		&gowid.ContainerWidget{
			IWidget: rightbr,
			D:       gowid.RenderFixed{},
		},
	})

	res.IWidget = cols
	res.Opt = opt
	res.up = up
	res.down = down

	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
