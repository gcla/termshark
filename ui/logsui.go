// Copyright 2019-2021 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/terminal"
	"github.com/gcla/termshark/v2/widgets/logviewer"
)

//======================================================================

// Dynamically load conv. If the convs window was last opened with a different filter, and the "limit to
// filter" checkbox is checked, then the data needs to be reloaded.
func openLogsUi(app gowid.IApp) {
	logsUi, err := logviewer.New(gowid.WidgetCallback{"cb",
		func(app gowid.IApp, w gowid.IWidget) {
			t := w.(*terminal.Widget)
			ecode := t.Cmd.ProcessState.ExitCode()
			// -1 for signals - don't show an error for that
			if ecode != 0 && ecode != -1 {
				d := OpenError(fmt.Sprintf(
					"Could not run logs viewer\n\n%s", t.Cmd.ProcessState), app)
				d.OnOpenClose(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
					closeLogsUi(app)
				}))
			} else {
				closeLogsUi(app)
			}
		},
	},
	)
	if err != nil {
		OpenError(fmt.Sprintf("Error launching terminal: %v", err), app)
		return
	}

	logsView := holder.New(logsUi)

	appViewNoKeys.SetSubWidget(logsView, app)
}

func closeLogsUi(app gowid.IApp) {
	appViewNoKeys.SetSubWidget(mainView, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
