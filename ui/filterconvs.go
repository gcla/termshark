// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gdamore/tcell"
)

//======================================================================

var filterConvsMenu1 *menu.Widget
var filterConvsMenu1Site *menu.SiteWidget
var filterConvsMenu2 *menu.Widget

type indirect struct {
	*holder.Widget
}

func buildFilterConvsMenu() {
	filterConvsMenu1Holder := &indirect{}
	filterConvsMenu2Holder := &indirect{}

	filterConvsMenu1 = menu.New("filterconvs1", filterConvsMenu1Holder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	filterConvsMenu2 = menu.New("filterconvs2", filterConvsMenu2Holder, fixed, menu.Options{
		Modal:             true,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	w := makeFilterConvsMenuWidget()
	filterConvsMenu1Site = menu.NewSite(menu.SiteOptions{
		XOffset: -3,
		YOffset: -3,
	})
	cols := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{IWidget: w, D: fixed},
		&gowid.ContainerWidget{IWidget: filterConvsMenu1Site, D: fixed},
	})
	filterConvsMenu1Holder.Widget = holder.New(cols)

	w2 := makeFilterConvs2MenuWidget()
	filterConvsMenu2Holder.Widget = holder.New(w2)
}

func makeFilterConvsMenuWidget() gowid.IWidget {
	menuItems := make([]menuutil.SimpleMenuItem, 0)

	for i, s := range []string{
		"Selected",
		"Not Selected",
		"...and Selected",
		"...or Selected",
		"...and not Selected",
		"...or not Selected",
	} {
		i2 := i
		menuItems = append(menuItems,
			menuutil.SimpleMenuItem{
				Txt: s,
				Key: gowid.MakeKey('1' + rune(i)),
				CB: func(app gowid.IApp, w2 gowid.IWidget) {
					convsUi.filterSelectedIndex = FilterCombinator(i2)
					filterConvsMenu2.Open(filterConvsMenu1Site, app)
				},
			},
		)
	}

	convListBox := menuutil.MakeMenuWithHotKeys(menuItems)

	return convListBox
}

func makeFilterConvs2MenuWidget() gowid.IWidget {
	menuItems := make([]menuutil.SimpleMenuItem, 0)

	for i, s := range []string{
		"A ↔ B",
		"A → B",
		"B → A",
		"A ↔ Any",
		"A → Any",
		"Any → A",
		"Any ↔ B",
		"Any → B",
		"B → Any",
	} {
		i2 := i
		menuItems = append(menuItems,
			menuutil.SimpleMenuItem{
				Txt: s,
				Key: gowid.MakeKey('1' + rune(i)),
				CB: func(app gowid.IApp, w2 gowid.IWidget) {
					filterConvsMenu1.Close(app)
					filterConvsMenu2.Close(app)
					convsUi.doFilterMenuOp(FilterMask(i2), app)
				},
			},
		)
	}

	convListBox := menuutil.MakeMenuWithHotKeys(menuItems)

	return convListBox
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
