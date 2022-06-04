// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"sync"

	"github.com/gcla/gowid"
)

//======================================================================

type commonSearchCallbacks struct {
	ticks int
}

func (s *commonSearchCallbacks) OnTick(app gowid.IApp) {
	s.ticks += 1
	if s.ticks >= 2 {
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			SetProgressIndeterminateFor(app, SearchOwns)
			SetSearchProgressWidget(app)
			loadSpinner.Update()
		}))
	}
}

func (s *commonSearchCallbacks) OnError(err error, app gowid.IApp) {
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		OpenError(err.Error(), app)
	}))
}

//======================================================================

type SearchStopper struct {
	RequestedMutex sync.Mutex
	Requested      bool
}

func (s *SearchStopper) RequestStop(app gowid.IApp) {
	s.RequestedMutex.Lock()
	defer s.RequestedMutex.Unlock()
	s.Requested = true
}

func (s *SearchStopper) DoIfStopped(f func()) {
	s.RequestedMutex.Lock()
	defer s.RequestedMutex.Unlock()
	if s.Requested {
		f()
		s.Requested = false
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
