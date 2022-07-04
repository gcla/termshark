// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"fmt"

	"github.com/flytam/filenamify"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/checkbox"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/disable"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/menu"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/ui/menuutil"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

var invalidNameErr = fmt.Errorf("Please ensure profile name can be used as a filename.")

// validProfileName makes sure the profile name is not in use AND can be embedded
// in a directory path. It's easier that way and not much of a limitation.
func validProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("No profile name provided.")
	}

	if termshark.StringInSlice(name, profiles.AllNames()) {
		return fmt.Errorf("Profile %s already exists.", name)
	}

	fname, err := filenamify.Filenamify(name, filenamify.Options{})
	if err != nil {
		return invalidNameErr
	}

	if name != fname {
		return invalidNameErr
	}

	return nil
}

func openNewProfile(app gowid.IApp) {
	var copyProfileDialog *dialog.Widget
	var redoDialog *dialog.Widget
	var basedOff string
	var invalidWidget *text.Widget
	var invalidText string
	var okFunc func(gowid.IApp, gowid.IWidget)

	openCopy := func() {
		copyProfileDialog.Open(appView, units(len(basedOff)+20), app)
	}

	openRedo := func() {
		invalidWidget.SetText(invalidText, app)
		redoDialog.Open(appView, units(len(invalidText)+10), app)
	}

	nameWidget := edit.New()
	nameWidgetExt := appkeys.New(
		nameWidget,
		func(ev *tcell.EventKey, app gowid.IApp) bool {
			res := false
			switch ev.Key() {
			case tcell.KeyEnter:
				okFunc(app, nameWidget)
				res = true
			}
			return res
		},
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	invalidText = "Placeholder"
	invalidWidget = text.New(invalidText)

	openAgainBtn := dialog.Button{
		Msg: "Ok",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, _ gowid.IWidget) {
			redoDialog.Close(app)
			openCopy()
		})),
	}

	redoView := framed.NewSpace(invalidWidget)

	redoDialog = dialog.New(
		redoView,
		dialog.Options{
			Buttons:         []dialog.Button{openAgainBtn},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
			FocusOnWidget:   true,
		},
	)

	var profileString string // what's displayed in the drop down button
	var profileDropDown *button.Widget
	var linkCheckBox *checkbox.Widget
	var profileMenu *menu.Widget

	okFunc = func(app gowid.IApp, _ gowid.IWidget) {
		copyProfileDialog.Close(app)

		name := nameWidget.Text()
		err := validProfileName(name)
		if err != nil {
			invalidText = err.Error()
			openRedo()
			return
		}

		prev := profiles.Current()

		err = profiles.CopyToAndUse(name)
		if err != nil {
			OpenError(err.Error(), app)
			return
		}

		cur := profiles.Current()

		// Set this after CopyAndUse so I can distinguish the prior Wireshark
		// profile link (if any) from the current. If there's a change, the current
		// source is reloaded.
		if linkCheckBox.IsChecked() && profileString != "" {
			profiles.SetConfIn(cur, "main.wireshark-profile", profileString)
		}

		err = ApplyCurrentProfile(app, prev, cur)
		if err != nil {
			OpenError(err.Error(), app)
			return
		}

		OpenMessage(fmt.Sprintf("Now using new profile %s.", name), appView, app)
	}

	okBtn := dialog.Button{
		Msg:    "Ok",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(okFunc)),
	}

	basedOff = fmt.Sprintf("This profile will be based off of %s.", profiles.CurrentName())

	linkCheckBox = checkbox.New(false)

	linkWidget := columns.NewFixed(text.New("Link to Wireshark: "), linkCheckBox)

	folderStrings := termshark.WiresharkProfileNames()

	enableWireshark := len(folderStrings) > 0

	if enableWireshark {
		profileString = folderStrings[0]
		profileDropDown = button.New(text.New(profileString))
	}

	menuItems := make([]menuutil.SimpleMenuItem, 0)

	for i, folder := range folderStrings {
		folderCopy := folder
		menuItems = append(menuItems,
			menuutil.SimpleMenuItem{
				Txt: folder,
				Key: gowid.MakeKey('1' + rune(i)),
				CB: func(app gowid.IApp, w2 gowid.IWidget) {
					profileString = folderCopy
					profileDropDown.SetSubWidget(text.New(profileString), app)
				},
			},
		)
	}

	lb, _ := menuutil.MakeMenuWithHotKeys(menuItems, nil)

	profileMenu = menu.New("profilemenu", lb, fixed, menu.Options{
		Modal:             true,
		OpenCloser:        &multiMenu1Opener,
		CloseKeysProvided: true,
		CloseKeys: []gowid.IKey{
			gowid.MakeKey('q'),
			gowid.MakeKeyExt(tcell.KeyLeft),
			gowid.MakeKeyExt(tcell.KeyEscape),
			gowid.MakeKeyExt(tcell.KeyCtrlC),
		},
	})

	profileMenuSite := menu.NewSite(menu.SiteOptions{YOffset: 1})

	if enableWireshark {
		profileDropDown.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
			multiMenu1Opener.OpenMenu(profileMenu, profileMenuSite, app)
		}))
	}

	s2Btn := disable.NewDisabled(profileDropDown)

	styledProfileBtn := styled.NewExt(
		s2Btn,
		gowid.MakePaletteRef("button"),
		gowid.MakePaletteRef("button-focus"),
	)

	linkCheckBox.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		s2Btn.Set(!linkCheckBox.IsChecked())
	}))

	dialogWidgets := make([]interface{}, 0, 8)
	dialogWidgets = append(dialogWidgets,
		text.New(basedOff),
		divider.NewBlank(),
		text.New("Please enter a name for this profile:"),
		divider.NewBlank(),
		framed.NewUnicode(nameWidgetExt),
	)

	// Add the option to link to a wireshark profile
	if enableWireshark {
		dialogWidgets = append(dialogWidgets,
			divider.NewBlank(),
			columns.NewWithDim(
				gowid.RenderWithWeight{1},
				&gowid.ContainerWidget{
					IWidget: linkWidget,
					D:       gowid.RenderFixed{},
				},
				text.New(" "),
				columns.NewFixed(profileMenuSite, styledProfileBtn),
			),
		)
	}

	newProfileView := framed.NewSpace(pile.NewFlow(dialogWidgets...))

	copyProfileDialog = dialog.New(
		newProfileView,
		dialog.Options{
			Buttons:         []dialog.Button{okBtn, dialog.Cancel},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
			FocusOnWidget:   true,
		},
	)

	openCopy()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
