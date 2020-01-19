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
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
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

func OpenMessage(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) {
	var al gowid.IHAlignment = hmiddle
	if strings.Count(msgt, "\n") > 0 {
		al = gowid.HAlignLeft{}
	}

	var view gowid.IWidget = text.New(msgt, text.Options{
		Align: al,
	})

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
		},
	)

	dialog.OpenExt(YesNo, openOver, fixed, fixed, app)
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
}

func ClosePleaseWait(app gowid.IApp) {
	PleaseWait.Close(app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
