// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"fmt"

	"github.com/flytam/filenamify"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gdamore/tcell/v2"
)

//======================================================================

var invalidNameErr = fmt.Errorf("Please ensure profile name can be used as a filename.")

// validProfileName makes sure the profile name is not in use AND can be embedded
// in a directory path. It's easier that way and not much of a limitation.
func validProfileName(name string) error {
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

	okFunc = func(app gowid.IApp, _ gowid.IWidget) {
		copyProfileDialog.Close(app)

		name := nameWidget.Text()
		err := validProfileName(name)
		if err != nil {
			invalidText = err.Error()
			openRedo()
			return
		}

		cur := profiles.Current()

		err = profiles.CopyToAndUse(name)
		if err != nil {
			OpenError(err.Error(), app)
			return
		}

		err = ApplyCurrentProfile(app, cur, profiles.Current())
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

	newProfileView := framed.NewSpace(
		pile.NewFlow(
			text.New(basedOff),
			divider.NewBlank(),
			text.New("Please enter a name for this profile:"),
			divider.NewBlank(),
			framed.NewUnicode(nameWidgetExt),
		),
	)

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
