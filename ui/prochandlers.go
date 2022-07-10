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
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/pcap"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type NoHandlers struct{}

//======================================================================

type updateCurrentCaptureInTitle struct {
	Ld *pcap.PacketLoader
}

var _ pcap.IBeforeBegin = updateCurrentCaptureInTitle{}
var _ pcap.IClear = updateCurrentCaptureInTitle{}

func MakeUpdateCurrentCaptureInTitle() updateCurrentCaptureInTitle {
	return updateCurrentCaptureInTitle{
		Ld: Loader,
	}
}

func (t updateCurrentCaptureInTitle) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PsmlCode != 0 {
		cap := t.Ld.String()
		if t.Ld.CaptureFilter() != "" {
			cap = fmt.Sprintf("%s (%s)", cap, t.Ld.CaptureFilter())
		}
		currentCapture.SetText(cap, app)
		currentCaptureWidgetHolder.SetSubWidget(currentCaptureWidget, app)
	}
}

func (t updateCurrentCaptureInTitle) OnClear(code pcap.HandlerCode, app gowid.IApp) {
	currentCaptureWidgetHolder.SetSubWidget(nullw, app)
}

//======================================================================

type updatePacketViews struct {
	Ld *pcap.PacketLoader
}

var _ pcap.IOnError = updatePacketViews{}
var _ pcap.IClear = updatePacketViews{}
var _ pcap.IBeforeBegin = updatePacketViews{}
var _ pcap.IAfterEnd = updatePacketViews{}

func MakePacketViewUpdater() updatePacketViews {
	res := updatePacketViews{}
	res.Ld = Loader
	return res
}

func (t updatePacketViews) OnClear(code pcap.HandlerCode, app gowid.IApp) {
	clearPacketViews(app)
	if packetListView != nil {
		updatePacketListWithData(t.Ld, app)
	}
}

func (t updatePacketViews) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PsmlCode == 0 {
		return
	}
	ch2 := Loader.PsmlFinishedChan
	clearPacketViews(app)
	t.Ld.PsmlLoader.Lock()
	defer t.Ld.PsmlLoader.Unlock()
	setPacketListWidgets(t.Ld, app)

	// Start this after widgets have been cleared, to get focus change
	termshark.TrackedGo(func() {
		fn2 := func() {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				updatePacketListWithData(Loader, app)
			}))
		}

		termshark.RunOnDoubleTicker(ch2, fn2,
			time.Duration(100)*time.Millisecond,
			time.Duration(2000)*time.Millisecond,
			10)
	}, Goroutinewg)
}

func (t updatePacketViews) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PsmlCode == 0 {
		return
	}
	updatePacketListWithData(t.Ld, app)
	StopEmptyStructViewTimer()
	StopEmptyHexViewTimer()
	log.Infof("Load operation complete")
}

func (t updatePacketViews) OnError(code pcap.HandlerCode, app gowid.IApp, err error) {
	if code&pcap.PsmlCode == 0 {
		return
	}
	log.Error(err)
	if !Running {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		RequestQuit()
	} else {
		if !profiles.ConfBool("main.suppress-tshark-errors", true) {
			var errstr string
			if kverr, ok := err.(gowid.KeyValueError); ok {
				errstr = termshark.KeyValueErrorString(kverr)
			} else {
				errstr = fmt.Sprintf("%v", err)
			}

			OpenLongError(errstr, app)
		}
		StopEmptyStructViewTimer()
		StopEmptyHexViewTimer()
	}
}

//======================================================================

type SimpleErrors struct{}

var _ pcap.IOnError = SimpleErrors{}

func (t SimpleErrors) OnError(code pcap.HandlerCode, app gowid.IApp, err error) {
	if code&pcap.NoneCode == 0 {
		return
	}
	log.Error(err)
	// Hack to avoid picking up errors at other parts of the load
	// cycle. There should be specific handlers for specific errors.
	if !profiles.ConfBool("main.suppress-tshark-errors", true) {
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			OpenError(fmt.Sprintf("%v", err), app)
		}))
	}
}

//======================================================================

type SaveRecents struct {
	Pcap   string
	Filter string
}

var _ pcap.IBeforeBegin = SaveRecents{}

func MakeSaveRecents(pcap string, filter string) SaveRecents {
	return SaveRecents{
		Pcap:   pcap,
		Filter: filter,
	}
}

func (t SaveRecents) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PsmlCode == 0 {
		return
	}
	// Run on main goroutine to avoid problems flagged by -race
	if t.Pcap != "" {
		termshark.AddToRecentFiles(t.Pcap)
	}
	if t.Filter != "" {
		// Run on main goroutine to avoid problems flagged by -race
		termshark.AddToRecentFilters(t.Filter)
	}
}

//======================================================================

type CancelledMessage struct{}

var _ pcap.IAfterEnd = CancelledMessage{}

func (t CancelledMessage) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PsmlCode == 0 {
		return
	}
	// Run on main goroutine to avoid problems flagged by -race
	if Loader.LoadWasCancelled() {
		// Only do this if the user isn't quitting the app,
		// otherwise it looks clumsy.
		if !QuitRequested {
			OpenError("Loading was cancelled.", app)
		}
	}
}

//======================================================================

type StartUIWhenThereArePackets struct{}

var _ pcap.IPsmlHeader = StartUIWhenThereArePackets{}

func (t StartUIWhenThereArePackets) OnPsmlHeader(code pcap.HandlerCode, app gowid.IApp) {
	StartUIOnce.Do(func() {
		close(StartUIChan)
	})
}

//======================================================================

type ClearWormholeState struct{}

var _ pcap.INewSource = ClearWormholeState{}

func (t ClearWormholeState) OnNewSource(code pcap.HandlerCode, app gowid.IApp) {
	if CurrentWormholeWidget != nil {
		CurrentWormholeWidget.Close()
	}
	CurrentWormholeWidget = nil
}

//======================================================================

type ClearMarksHandler struct{}

var _ pcap.IClear = checkGlobalJumpAfterPsml{}
var _ pcap.INewSource = checkGlobalJumpAfterPsml{}

func clearMarks() {
	for k := range marksMap {
		delete(marksMap, k)
	}
	lastJumpPos = -1
}

func (t checkGlobalJumpAfterPsml) OnNewSource(code pcap.HandlerCode, app gowid.IApp) {
	clearMarks()
}

func (t checkGlobalJumpAfterPsml) OnClear(code pcap.HandlerCode, app gowid.IApp) {
	clearMarks()
}

//======================================================================

func clearSearchData(app gowid.IApp) {
	if SearchWidget != nil {
		SearchWidget.Clear(app)
	}
}

type ManageSearchData struct{}

var _ pcap.INewSource = ManageSearchData{}
var _ pcap.IClear = ManageSearchData{}

// Make sure that existing stream widgets are discarded if the user loads a new pcap.
func (t ManageSearchData) OnNewSource(c pcap.HandlerCode, app gowid.IApp) {
	clearSearchData(app)
}

func (t ManageSearchData) OnClear(c pcap.HandlerCode, app gowid.IApp) {
	clearSearchData(app)
}

//======================================================================

type checkGlobalJumpAfterPsml struct {
	Jump termshark.GlobalJumpPos
}

var _ pcap.IAfterEnd = checkGlobalJumpAfterPsml{}

func MakeCheckGlobalJumpAfterPsml(jmp termshark.GlobalJumpPos) checkGlobalJumpAfterPsml {
	return checkGlobalJumpAfterPsml{
		Jump: jmp,
	}
}

func (t checkGlobalJumpAfterPsml) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	// Run on main goroutine to avoid problems flagged by -race
	if code&pcap.PsmlCode == 0 {
		return
	}
	if QuitRequested {
		return
	}
	if t.Jump.Filename == Loader.Pcap() {
		if packetListView != nil {
			tableRow, err := tableRowFromPacketNumber(t.Jump.Pos)
			if err != nil {
				OpenError(err.Error(), app)
			} else {

				tableCol := 0
				curTablePos, err := packetListView.FocusXY()
				if err == nil {
					tableCol = curTablePos.Column
				}

				packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
			}
		}
	}
}

//======================================================================

// used for the pdml loader
type SetStructWidgets struct {
	Ld *pcap.PacketLoader
}

var _ pcap.IOnError = SetStructWidgets{}

var _ pcap.IBeforeBegin = SetStructWidgets{}
var _ pcap.IAfterEnd = SetStructWidgets{}

func (s SetStructWidgets) BeforeBegin(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PdmlCode == 0 {
		return
	}
	s2ch := s.Ld.Stage2FinishedChan

	termshark.TrackedGo(func() {
		fn2 := func() {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				setLowerWidgets(app)
			}))
		}

		termshark.RunOnDoubleTicker(s2ch, fn2,
			time.Duration(100)*time.Millisecond,
			time.Duration(2000)*time.Millisecond,
			10)
	}, Goroutinewg)
}

// Close the channel before the callback. When the global loader state is idle,
// app.Quit() will stop accepting app callbacks, so the goroutine that waits
// for ch to be closed will never terminate.
func (s SetStructWidgets) AfterEnd(code pcap.HandlerCode, app gowid.IApp) {
	if code&pcap.PdmlCode == 0 {
		return
	}
	setLowerWidgets(app)
	StopEmptyHexViewTimer()
	StopEmptyStructViewTimer()
}

func (s SetStructWidgets) OnError(code pcap.HandlerCode, app gowid.IApp, err error) {
	if code&pcap.PdmlCode == 0 {
		return
	}
	log.Error(err)
	// Hack to avoid picking up errors at other parts of the load
	// cycle. There should be specific handlers for specific errors.
	if s.Ld.PdmlLoader.IsLoading() {
		if !profiles.ConfBool("main.suppress-tshark-errors", true) {
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				OpenLongError(fmt.Sprintf("%v", err), app)
			}))
		}
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
