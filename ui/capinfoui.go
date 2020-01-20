// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"os"
	"strings"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/capinfo"
	"github.com/gcla/termshark/v2/pcap"
	log "github.com/sirupsen/logrus"
)

var CapinfoLoader *capinfo.Loader

var CapinfoData string
var CapinfoTime time.Time

//======================================================================

func startCapinfo(app gowid.IApp) {
	if Loader.PcapPdml == "" {
		OpenError("No pcap loaded.", app)
		return
	}

	fi, err := os.Stat(Loader.PcapPdml)
	if err != nil || CapinfoTime.Before(fi.ModTime()) {
		CapinfoLoader = capinfo.NewLoader(capinfo.MakeCommands(), Loader.SourceContext())

		handler := capinfoParseHandler{
			app: app,
		}

		CapinfoLoader.StartLoad(
			Loader.PcapPdml,
			app,
			&handler,
		)
	} else {
		OpenMessage(CapinfoData, appView, app)
	}
}

//======================================================================

type capinfoParseHandler struct {
	app              gowid.IApp
	tick             *time.Ticker // for updating the spinner
	stop             chan struct{}
	pleaseWaitClosed bool
}

var _ capinfo.ICapinfoCallbacks = (*capinfoParseHandler)(nil)

func (t *capinfoParseHandler) OnCapinfoData(data string, ch chan struct{}) {
	CapinfoData = strings.Replace(data, "\r\n", "\n", -1) // For windows...
	fi, err := os.Stat(Loader.PcapPdml)
	if err != nil {
		log.Warnf("Could not read mtime from pcap %s: %v", Loader.PcapPdml, err)
	} else {
		CapinfoTime = fi.ModTime()
	}
	close(ch)
}

func (t *capinfoParseHandler) AfterCapinfoEnd(success bool, ch chan<- struct{}) {
	close(ch)
}

func (t *capinfoParseHandler) BeforeBegin(closeMe chan<- struct{}) {
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

func (t *capinfoParseHandler) AfterEnd(closeMe chan<- struct{}) {
	close(closeMe)
	t.app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(t.app)
		}

		OpenMessage(CapinfoData, appView, app)
	}))
	close(t.stop)
}

//======================================================================

func clearCapinfoState() {
	CapinfoTime = time.Time{}
}

//======================================================================

type ManageCapinfoCache struct{}

var _ pcap.INewSource = ManageCapinfoCache{}

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageCapinfoCache) OnNewSource(closeMe chan<- struct{}) {
	clearCapinfoState()
	close(closeMe)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
