// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/termshark/v2/pkg/capinfo"
	"github.com/gcla/termshark/v2/pkg/pcap"
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
		CapinfoLoader = capinfo.NewLoader(capinfo.MakeCommands(), Loader.Context())

		handler := capinfoParseHandler{}

		CapinfoLoader.StartLoad(
			Loader.PcapPdml,
			app,
			&handler,
		)
	} else {
		OpenMessageForCopy(CapinfoData, appView, app)
	}
}

//======================================================================

type capinfoParseHandler struct {
	tick             *time.Ticker // for updating the spinner
	stop             chan struct{}
	pleaseWaitClosed bool
}

var _ capinfo.ICapinfoCallbacks = (*capinfoParseHandler)(nil)
var _ pcap.IBeforeBegin = (*capinfoParseHandler)(nil)
var _ pcap.IAfterEnd = (*capinfoParseHandler)(nil)

func (t *capinfoParseHandler) OnCapinfoData(data string) {
	CapinfoData = strings.Replace(data, "\r\n", "\n", -1) // For windows...
	fi, err := os.Stat(Loader.PcapPdml)
	if err != nil {
		log.Warnf("Could not read mtime from pcap %s: %v", Loader.PcapPdml, err)
	} else {
		CapinfoTime = fi.ModTime()
	}
}

func (t *capinfoParseHandler) AfterCapinfoEnd(success bool) {
}

func (t *capinfoParseHandler) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.CapinfoCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenPleaseWait(appView, app)
	}))

	t.tick = time.NewTicker(time.Duration(200) * time.Millisecond)
	t.stop = make(chan struct{})

	termshark.TrackedGo(func() {
	Loop:
		for {
			select {
			case <-t.tick.C:
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					pleaseWaitSpinner.Update()
				}))
			case <-t.stop:
				break Loop
			}
		}
	}, Goroutinewg)
}

func (t *capinfoParseHandler) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.CapinfoCode == 0 {
		return
	}
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		if !t.pleaseWaitClosed {
			t.pleaseWaitClosed = true
			ClosePleaseWait(app)
		}

		OpenMessageForCopy(CapinfoData, appView, app)
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
var _ pcap.IClear = ManageCapinfoCache{}

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageCapinfoCache) OnNewSource(pcap.HandlerCode, gowid.IApp) {
	clearCapinfoState()
}

func (t ManageCapinfoCache) OnClear(pcap.HandlerCode, gowid.IApp) {
	clearCapinfoState()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
