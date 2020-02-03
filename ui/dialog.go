// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/widgets/appkeys"
)

//======================================================================

var (
	fixed      gowid.RenderFixed
	flow       gowid.RenderFlow
	hmiddle    gowid.HAlignMiddle
	vmiddle    gowid.VAlignMiddle
	YesNo      *dialog.Widget
	PleaseWait *dialog.Widget
)

type textID string

func (t textID) ID() interface{} {
	return string(t)
}

// So that I can capture ctrl-c etc before the dialog
type copyable struct {
	*dialog.Widget
	wrapper gowid.IWidget
}

func (w *copyable) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return w.wrapper.UserInput(ev, size, focus, app)
}

func OpenMessage(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) {
	openMessage(msgt, openOver, false, app)
}

func OpenMessageForCopy(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) {
	openMessage(msgt, openOver, true, app)
}

func openMessage(msgt string, openOver gowid.ISettableComposite, focusOnWidget bool, app gowid.IApp) {
	var al gowid.IHAlignment = hmiddle
	if strings.Count(msgt, "\n") > 0 {
		al = gowid.HAlignLeft{}
	}

	var view gowid.IWidget = text.NewCopyable(msgt, textID(msgt),
		styled.UsePaletteIfSelectedForCopy{Entry: "copy-mode-alt"},
		text.Options{
			Align: al,
		},
	)

	view = selectable.New(view)

	view = hpadding.New(
		view,
		hmiddle,
		gowid.RenderFixed{},
	)

	view = framed.NewSpace(view)

	YesNo = dialog.New(
		view,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
			FocusOnWidget:   focusOnWidget,
		},
	)

	wrapper := appkeys.New(
		appkeys.New(
			YesNo,
			copyModeExitKeys20,
			appkeys.Options{
				ApplyBefore: true,
			},
		),
		copyModeEnterKeys,
		appkeys.Options{
			ApplyBefore: true,
		},
	)

	dialog.OpenExt(
		&copyable{
			Widget:  YesNo,
			wrapper: wrapper,
		}, openOver, fixed, fixed, app,
	)
}

func OpenTemplatedDialog(container gowid.ISettableComposite, tmplName string, app gowid.IApp) {
	YesNo = dialog.New(framed.NewSpace(
		text.New(termshark.TemplateToString(Templates, tmplName, TemplateData)),
	),
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-buttons"),
		},
	)
	YesNo.Open(container, ratio(0.5), app)
}

func OpenPleaseWait(container gowid.ISettableComposite, app gowid.IApp) {
	PleaseWait.Open(container, fixed, app)
	if Fin != nil {
		Fin.Activate()
	}
}

func ClosePleaseWait(app gowid.IApp) {
	PleaseWait.Close(app)
	if Fin != nil {
		Fin.Deactivate()
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
