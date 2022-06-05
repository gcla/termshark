// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/framed"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/paragraph"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
)

//======================================================================

// SuggestSwitchingTerm will open a dialog asking the user if they would like to try
// a more colorful TERM setting.
func SuggestSwitchingTerm(app gowid.IApp) {
	var switchTerm *dialog.Widget

	Yes := dialog.Button{
		Msg: "Yes",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			termshark.ShouldSwitchTerminal = true
			switchTerm.Close(app)
			RequestQuit()
		})),
	}
	No := dialog.Button{
		Msg: "No",
	}
	NoAsk := dialog.Button{
		Msg: "No, don't ask",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			profiles.SetConf("main.disable-term-helper", true)
			switchTerm.Close(app)
		})),
	}

	term := os.Getenv("TERM")
	term256 := term + "-256color"

	switchTerm = dialog.New(
		framed.NewSpace(paragraph.New(fmt.Sprintf("Termshark is running with TERM=%s. The terminal database contains %s. Would you like to switch for a more colorful experience? Termshark will need to restart.", term, term256))),
		dialog.Options{
			Buttons:         []dialog.Button{Yes, No, NoAsk},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
			FocusOnWidget:   false,
		},
	)

	switchTerm.Open(appView, gowid.RenderWithRatio{R: 0.5}, app)
}

//======================================================================

// IsTerminalLegible will open up a dialog asking the user to confirm that their
// running termshark is legible, having upgraded the TERM variable to a 256-color
// version and restarted.
func IsTerminalLegible(app gowid.IApp) {

	var saveTerm *dialog.Widget

	YesSave := dialog.Button{
		Msg: "Yes",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			profiles.SetConf("main.term", os.Getenv("TERM"))
			saveTerm.Close(app)
		})),
	}
	NoSave := dialog.Button{
		Msg: "No",
	}

	saveTerm = dialog.New(
		framed.NewSpace(paragraph.New(fmt.Sprintf("Do you want to save TERM=%s in termshark's config to use as the default?", os.Getenv("TERM")))),
		dialog.Options{
			Buttons:         []dialog.Button{YesSave, NoSave},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
			FocusOnWidget:   false,
		},
	)

	tick := time.NewTicker(time.Duration(1) * time.Second)
	stopC := make(chan struct{})

	var legibleTerm *dialog.Widget

	No := dialog.Button{
		Msg: "No",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			close(stopC)
			termshark.ShouldSwitchBack = true
			legibleTerm.Close(app)
			RequestQuit()
		})),
	}
	Yes := dialog.Button{
		Msg: "Yes",
		Action: gowid.MakeWidgetCallback("exec", gowid.WidgetChangedFunction(func(app gowid.IApp, w gowid.IWidget) {
			close(stopC)
			legibleTerm.Close(app)
			saveTerm.Open(appView, gowid.RenderWithRatio{R: 0.5}, app)
		})),
	}

	secs := 10

	tw := func(count int) *paragraph.Widget {
		return paragraph.New(fmt.Sprintf("Is the terminal legible? If no selection is made, termshark will revert to its original TERM setting in %d seconds.", secs))
	}

	message := holder.New(tw(secs))

	termshark.TrackedGo(func() {
	Loop:
		for {
			select {
			case <-tick.C:
				secs--
				switch {
				case secs >= 0:
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						message.SetSubWidget(tw(secs), app)
					}))
				case secs < 0:
					tick.Stop()
					close(stopC)
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						termshark.ShouldSwitchBack = true
						legibleTerm.Close(app)
						RequestQuit()
					}))
				}
			case <-stopC:
				break Loop
			}
		}
	}, Goroutinewg)

	legibleTerm = dialog.New(
		framed.NewSpace(message),
		dialog.Options{
			Buttons:         []dialog.Button{Yes, No},
			NoShadow:        true,
			BackgroundStyle: gowid.MakePaletteRef("dialog"),
			BorderStyle:     gowid.MakePaletteRef("dialog"),
			ButtonStyle:     gowid.MakePaletteRef("dialog-button"),
			Modal:           true,
			FocusOnWidget:   false,
			StartIdx:        1,
		},
	)

	legibleTerm.Open(appView, gowid.RenderWithRatio{R: 0.5}, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
