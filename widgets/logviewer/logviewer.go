// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

// Package logviewer provides a widget to view termshark's log file in a terminal
// via a pager program.
package logviewer

import (
	"fmt"
	"os"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/terminal"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
)

//======================================================================

type Widget struct {
	gowid.IWidget
}

// New - a bit clumsy, UI will always be legit, but error represents terminal failure
func New(cb gowid.IWidgetChangedCallback) (*Widget, error) {
	logfile := termshark.CacheFile("termshark.log")

	var args []string
	pager := termshark.ConfString("main.pager", "")
	if pager == "" {
		pager = os.Getenv("PAGER")
	}
	if pager == "" {
		args = []string{"less", "+G", logfile}
	} else {
		args = []string{"sh", "-c", fmt.Sprintf("%s %s", pager, logfile)}
	}

	var term gowid.IWidget
	var termC *terminal.Widget
	var errTerm error
	termC, errTerm = terminal.New(args)
	if errTerm != nil {
		term = null.New()
	} else {
		termC.OnProcessExited(cb)
		term = termC
	}

	header := hpadding.New(
		text.New(fmt.Sprintf("Logs - %s", logfile)),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	main := pile.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: header,
			D:       gowid.RenderWithUnits{U: 2},
		},
		&gowid.ContainerWidget{
			IWidget: term,
			D:       gowid.RenderWithWeight{W: 1.0},
		},
	})

	res := &Widget{
		IWidget: main,
	}

	return res, errTerm
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
