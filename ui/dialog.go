// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/gowid/widgets/paragraph"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/selectable"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/widgets/appkeys"
	"github.com/gcla/termshark/v2/widgets/framefocus"
	"github.com/gcla/termshark/v2/widgets/minibuffer"
	"github.com/gcla/termshark/v2/widgets/scrollabletext"
	"github.com/gcla/termshark/v2/widgets/withscrollbar"
)

//======================================================================

var (
	fixed      gowid.RenderFixed
	flow       gowid.RenderFlow
	hmiddle    gowid.HAlignMiddle
	hleft      gowid.HAlignLeft
	vmiddle    gowid.VAlignMiddle
	YesNo      *dialog.Widget
	MiniBuffer *minibuffer.Widget
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

func OpenMessage(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) *dialog.Widget {
	return openMessage(msgt, openOver, false, false, app)
}

func OpenLongMessage(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) *dialog.Widget {
	return openMessage(msgt, openOver, false, true, app)
}

func OpenMessageForCopy(msgt string, openOver gowid.ISettableComposite, app gowid.IApp) *dialog.Widget {
	return openMessage(msgt, openOver, true, false, app)
}

func openMessage(msgt string, openOver gowid.ISettableComposite, selectableWidget bool, doFlow bool, app gowid.IApp) *dialog.Widget {
	var dh gowid.IWidgetDimension = fixed
	var dw gowid.IWidgetDimension = fixed

	if doFlow {
		dh = flow
		dw = ratio(0.7)
	}

	var al gowid.IHAlignment = hmiddle
	if strings.Count(msgt, "\n") > 0 || doFlow {
		al = hleft
	}

	var view gowid.IWidget = text.NewCopyable(msgt, textID(msgt),
		styled.UsePaletteIfSelectedForCopy{Entry: "copy-mode-alt"},
		text.Options{
			Align: al,
		},
	)

	if selectableWidget {
		view = selectable.New(view)
	}

	view = hpadding.New(
		view,
		hmiddle,
		dh,
	)

	if selectableWidget {
		view = framefocus.NewSlim(view)
	}

	view = framed.NewSpace(view)

	YesNo = dialog.New(
		view,
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
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
		}, openOver, dw, dh, app,
	)

	return YesNo
}

func OpenTemplatedDialog(container gowid.ISettableComposite, tmplName string, app gowid.IApp) *dialog.Widget {
	msg := termshark.TemplateToString(Templates, tmplName, TemplateData)
	lines := strings.Split(msg, "\n")

	ws := make([]interface{}, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			ws = append(ws, text.New(line))
		} else {
			words := strings.Fields(line)
			for i := 0; i < len(words); i++ {
				words[i] = strings.ReplaceAll(words[i], "_", " ")
			}
			ws = append(ws, paragraph.NewWithWords(words...))
		}
	}
	body := pile.NewFlow(ws...)

	YesNo = dialog.New(
		framed.NewSpace(body),
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			Modal:           true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)

	YesNo.Open(container, ratio(0.5), app)

	return YesNo
}

func OpenTemplatedDialogExt(container gowid.ISettableComposite, tmplName string, width gowid.IWidgetDimension, height gowid.IWidgetDimension, app gowid.IApp) *dialog.Widget {
	YesNo = dialog.New(framed.NewSpace(
		withscrollbar.New(
			scrollabletext.New(
				termshark.TemplateToString(Templates, tmplName, TemplateData),
			),
			withscrollbar.Options{
				HideIfContentFits: true,
			},
		),
	),
		dialog.Options{
			Buttons:         dialog.CloseOnly,
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
		},
	)
	dialog.OpenExt(YesNo, container, width, height, app)
	return YesNo
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
