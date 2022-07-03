// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/terminal"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/widgets/fileviewer"
	log "github.com/sirupsen/logrus"
)

//======================================================================

func pager() string {
	res := profiles.ConfString("main.pager", "")
	if res == "" {
		res = os.Getenv("PAGER")
	}
	return res
}

// Dynamically load conv. If the convs window was last opened with a different filter, and the "limit to
// filter" checkbox is checked, then the data needs to be reloaded.
func openLogsUi(app gowid.IApp) {
	openFileUi(termshark.CacheFile("termshark.log"), false, fileviewer.Options{
		Name:       "Logs",
		GoToBottom: true,
		Pager:      pager(),
	}, app)
}

func openConfigUi(app gowid.IApp) {
	tmp, err := ioutil.TempFile("", "termshark-*.toml")
	if err != nil {
		OpenError(fmt.Sprintf("Could not create temp file: %v", err), app)
		return
	}
	tmp.Close()

	err = profiles.WriteConfigAs(tmp.Name())
	if err != nil {
		OpenError(fmt.Sprintf("Could not run config viewer\n\n%v", err), app)
	} else {
		openFileUi(tmp.Name(), true, fileviewer.Options{
			Name:  "Config",
			Pager: pager(),
		}, app)
	}
}

func openFileUi(file string, delete bool, opt fileviewer.Options, app gowid.IApp) {
	logsUi, err := fileviewer.New(file,
		gowid.WidgetCallback{"cb",
			func(app gowid.IApp, w gowid.IWidget) {
				t := w.(*terminal.Widget)
				ecode := t.Cmd.ProcessState.ExitCode()
				// -1 for signals - don't show an error for that
				if ecode != 0 && ecode != -1 {
					d := OpenError(fmt.Sprintf("Could not run file viewer\n\n%s", t.Cmd.ProcessState), app)
					d.OnOpenClose(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
						closeFileUi(app)
					}))
				} else {
					closeFileUi(app)
				}
				if delete && false {
					err := os.Remove(file)
					if err != nil {
						log.Warnf("Problem deleting %s: %v", file, err)
					}
				}
			},
		},
		opt,
	)
	if err != nil {
		OpenError(fmt.Sprintf("Error launching terminal: %v", err), app)
		return
	}

	logsView := holder.New(logsUi)

	appViewNoKeys.SetSubWidget(logsView, app)
}

func closeFileUi(app gowid.IApp) {
	appViewNoKeys.SetSubWidget(mainView, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
