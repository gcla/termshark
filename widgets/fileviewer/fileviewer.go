// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

// Package fileviewer provides a widget to view a text file in a terminal
// via a pager program.
package fileviewer

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/terminal"
	"github.com/gcla/gowid/widgets/text"
)

//======================================================================

type Options struct {
	Name       string
	GoToBottom bool
	Pager      string
}

type Widget struct {
	gowid.IWidget
	opt Options
}

// New - a bit clumsy, UI will always be legit, but error represents terminal failure
func New(vfile string, cb gowid.IWidgetChangedCallback, opts ...Options) (*Widget, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	var args []string

	if opt.Pager == "" {
		if opt.GoToBottom {
			args = []string{"less", "+G", vfile}
		} else {
			args = []string{"less", vfile}
		}
	} else {
		args = []string{"sh", "-c", fmt.Sprintf("%s %s", opt.Pager, vfile)}
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
		text.New(fmt.Sprintf("%s - %s", opt.Name, vfile)),
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
		opt:     opt,
	}

	return res, errTerm
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
