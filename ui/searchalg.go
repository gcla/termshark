// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/widgets/search"
)

//======================================================================

// PacketSearcher coordinates a packet search and communicates results back from the
// search implementations via resultChan.
type PacketSearcher struct {
	resultChan chan search.IntermediateResult
}

var _ search.IAlgorithm = (*PacketSearcher)(nil)

//======================================================================

// SearchPackets looks for the given search term in the currently loaded packets. It
// is written generically, with the specifics of the packet details to be searched provided
// by a set of callbacks. These give the search algorithm the starting position, the mechanics
// of the search, and so on. An instance of a search can return a matching position, or a
// value indicating that the algorithm needs to wait until packet data is available (e.g.
// if PDML data needs to be searched but is not currently loaded). If a match is found, the
// callbacks also determine how to update the UI to represent the match.
func (w *PacketSearcher) SearchPackets(term search.INeedle, cbs search.ICallbacks, app gowid.IApp) {

	if packetListView == nil {
		cbs.OnError(fmt.Errorf("No packets to search"), app)
		return
	}

	cbs.Reset(app)

	currentPos, err := cbs.StartingPosition()
	startPos := currentPos
	// currentPacket will be 1-based
	if err != nil {
		cbs.OnError(err, app)
		return
	}

	stopCurrentSearch = cbs
	progressOwner = SearchOwns

	searchStop.RemoveOnClick(gowid.CallbackID{
		Name: "searchstop",
	})
	searchStop.OnClick(gowid.MakeWidgetCallback("searchstop", func(app gowid.IApp, _ gowid.IWidget) {
		cbs.RequestStop(app)
	}))

	tickInterval := time.Duration(200) * time.Millisecond
	tick := time.NewTicker(tickInterval)

	resumeAt := -1
	var resAt interface{}

	// Computationally bound searching goroutine - may have to terminate if it runs out of
	// packets to search while they're loaded
	termshark.TrackedGo(func() {
		cbs.SearchPacketsFrom(currentPos, startPos, term, app)
	}, Goroutinewg)

	// This goroutine exists so that at a regular interval, I can update progress. I want
	// the main searching goroutine to be doing the computation and not having to cooperate
	// with a timer interrupt
	termshark.TrackedGo(func() {

		res := search.Result{}

		defer func() {
			stopCurrentSearch = nil
			cbs.SearchPacketsResult(res, app)
		}()

	Loop:
		for {
			select {
			case <-tick.C:
				cbs.OnTick(app)

				if resumeAt != -1 {
					termshark.TrackedGo(func() {
						cbs.SearchPacketsFrom(resAt, startPos, term, app)
					}, Goroutinewg)
					resumeAt = -1
				}

			case sres := <-w.resultChan:
				if sres.ResumeAt == nil {
					// Search is finished
					res = sres.Res
					break Loop
				} else {
					resumeAt = sres.ResumeAt.PacketNumber()
					resAt = sres.ResumeAt

					// go to 0-based for cache lookup
					resumeAtZeroBased := resumeAt - 1
					app.Run(gowid.RunFunction(func(app gowid.IApp) {
						pktsPerLoad := Loader.PacketsPerLoad()

						CacheRequests = append(CacheRequests, pcap.LoadPcapSlice{
							Row:           (resumeAtZeroBased / pktsPerLoad) * pktsPerLoad,
							CancelCurrent: true,
						})
						CacheRequestsChan <- struct{}{}
					}))
				}
			}
		}
	}, Goroutinewg)

}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
