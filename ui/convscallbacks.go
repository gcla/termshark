// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"strings"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
)

//======================================================================

type IOnDataSync interface {
	OnData(data string, app gowid.IApp)
	OnCancel(gowid.IApp)
}

type convsParseHandler struct {
	app              gowid.IApp
	tick             *time.Ticker // for updating the spinner
	stop             chan struct{}
	ondata           IOnDataSync
	pleaseWaitClosed bool
}

func (t *convsParseHandler) OnData(data string, ch chan struct{}) {
	data = strings.Replace(data, "\r\n", "\n", -1) // For windows...

	if t.ondata != nil {
		t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
			t.ondata.OnData(data, app)
		}))
	}
	close(ch)
}

func (t *convsParseHandler) AfterDataEnd(success bool, ch chan<- struct{}) {
	if t.ondata != nil && !success {
		t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
			t.ondata.OnCancel(app)
		}))
	}
	close(ch)
}

func (t *convsParseHandler) BeforeBegin(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenPleaseWait(appView, t.app)
	}))

	t.tick = time.NewTicker(time.Duration(200) * time.Millisecond)
	t.stop = make(chan struct{})

	termshark.TrackedGo(func() {
	Loop:
		for {
			select {
			case <-t.tick.C:
				t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
					pleaseWaitSpinner.Update()
				}))
			case <-t.stop:
				break Loop
			}
		}
	}, Goroutinewg)
}

func (t *convsParseHandler) AfterEnd(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(t.app)
		}
	}))
	close(t.stop)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
