// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/cellmod"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/keypress"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

type SimpleMenuItem struct {
	Txt string
	Key gowid.IKey
	CB  gowid.WidgetChangedFunction
}

func MakeMenuDivider() SimpleMenuItem {
	return SimpleMenuItem{}
}

func MakeMenuWithHotKeys(items []SimpleMenuItem) gowid.IWidget {
	menu1Widgets := make([]gowid.IWidget, len(items))
	menu1HotKeys := make([]gowid.IWidget, len(items))

	// Figure out the length of the longest hotkey string representation
	max := 0
	for _, w := range items {
		if w.Txt != "" {
			k := fmt.Sprintf("%v", w.Key)
			if len(k) > max {
				max = len(k)
			}
		}
	}

	// Construct the hotkey widget and menu item widget for each menu entry
	for i, w := range items {
		if w.Txt != "" {
			load1B := button.NewBare(text.New(w.Txt))
			var ks string
			if w.Key != nil {
				ks = fmt.Sprintf("%v", w.Key)
			}
			load1K := button.NewBare(text.New(ks))
			load1CB := gowid.MakeWidgetCallback("cb", w.CB)
			load1B.OnClick(load1CB)
			if w.Key != nil {
				load1K.OnClick(load1CB)
			}
			menu1Widgets[i] = load1B
			menu1HotKeys[i] = load1K
		}
	}
	for i, w := range menu1Widgets {
		if w != nil {
			menu1Widgets[i] = styled.NewInvertedFocus(selectable.New(w), gowid.MakePaletteRef("default"))
		}
	}
	for i, w := range menu1HotKeys {
		if w != nil {
			menu1HotKeys[i] = styled.NewInvertedFocus(w, gowid.MakePaletteRef("default"))
		}
	}

	// Build the menu "row" for each menu entry
	menu1Widgets2 := make([]gowid.IWidget, len(menu1Widgets))
	for i, w := range menu1Widgets {
		if w == nil {
			menu1Widgets2[i] = divider.NewUnicode()
		} else {
			menu1Widgets2[i] = columns.New(
				[]gowid.IContainerWidget{
					&gowid.ContainerWidget{
						IWidget: hpadding.New(
							// size is translated from flowwith{20} to fixed; fixed gives size 6, flowwith aligns right to 12
							hpadding.New(
								selectable.NewUnselectable( // don't want to be able to navigate to the hotkey itself
									menu1HotKeys[i],
								),
								gowid.HAlignRight{},
								fixed,
							),
							gowid.HAlignLeft{},
							gowid.RenderFlowWith{C: max},
						),
						D: fixed,
					},
					&gowid.ContainerWidget{
						IWidget: text.New("| "),
						D:       fixed,
					},
					&gowid.ContainerWidget{
						IWidget: w,
						D:       fixed,
					},
				},
				columns.Options{
					StartColumn: 2,
				},
			)
		}
	}

	menu1cwidgets := make([]gowid.IContainerWidget, len(menu1Widgets2))
	for i, w := range menu1Widgets2 {
		var dim gowid.IWidgetDimension
		if menu1Widgets[i] != nil {
			dim = fixed
		} else {
			dim = gowid.RenderFlow{}
		}
		menu1cwidgets[i] = &gowid.ContainerWidget{
			IWidget: w,
			D:       dim,
		}
	}

	keys := make([]gowid.IKey, 0)
	for _, i := range items {
		if i.Key != nil {
			keys = append(keys, i.Key)
		}
	}

	// Surround the menu with a widget that captures the hotkey keypresses
	menuListBox1 := keypress.New(
		cellmod.Opaque(
			styled.New(
				framed.NewUnicode(
					pile.New(menu1cwidgets, pile.Options{
						Wrap: true,
					}),
				),
				gowid.MakePaletteRef("default"),
			),
		),
		keypress.Options{
			Keys: keys,
		},
	)

	menuListBox1.OnKeyPress(keypress.MakeCallback("key1", func(app gowid.IApp, w gowid.IWidget, k gowid.IKey) {
		for _, r := range items {
			if r.Key != nil && gowid.KeysEqual(k, r.Key) {
				r.CB(app, w)
				break
			}
		}
	}))

	return menuListBox1
}

//======================================================================

type NextMenu struct {
	Cur       *menu.Widget
	Next      *menu.Widget // nil if menu is nil
	Site      *menu.SiteWidget
	Container gowid.IFocus // container holding menu buttons, etc
	Focus     int          // index of next menu in container
}

func MakeMenuNavigatingKeyPress(left *NextMenu, right *NextMenu) appkeys.KeyInputFn {
	return func(evk *tcell.EventKey, app gowid.IApp) bool {
		return MenuNavigatingKeyPress(evk, left, right, app)
	}
}

func MenuNavigatingKeyPress(evk *tcell.EventKey, left *NextMenu, right *NextMenu, app gowid.IApp) bool {
	res := false
	switch evk.Key() {
	case tcell.KeyLeft:
		if left != nil {
			left.Cur.Close(app)
			left.Next.Open(left.Site, app)
			left.Container.SetFocus(app, left.Focus) // highlight next menu selector
			res = true
		}
	case tcell.KeyRight:
		if right != nil {
			right.Cur.Close(app)
			right.Next.Open(right.Site, app)
			right.Container.SetFocus(app, right.Focus) // highlight next menu selector
			res = true
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
