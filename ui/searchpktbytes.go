// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/widgets/search"
)

//======================================================================

// BytesResult represents a match for a search within the bytes of the packets loaded. A match
// is a packet number, and the position within the byte array representing the packet's data.
type BytesResult struct {
	PacketNum int
	PacketPos int
	PacketRow int
}

func (s BytesResult) PacketNumber() int {
	return s.PacketNum
}

//======================================================================

// Search in the packet hex view
//
type BytesSearchCallbacks struct {
	*commonSearchCallbacks
	*SearchStopper
	term   search.INeedle
	search chan search.IntermediateResult
}

var _ search.IRequestStop = (*BytesSearchCallbacks)(nil)
var _ search.ICallbacks = (*BytesSearchCallbacks)(nil)

func (w *BytesSearchCallbacks) Reset(app gowid.IApp) {
	w.SearchStopper.Requested = false
	w.ticks = 0
}

func (w *BytesSearchCallbacks) StartingPosition() (interface{}, error) {
	tablePos, err := packetListView.FocusXY() // e.g. table position 5
	if err != nil {
		return BytesResult{}, err
	}

	p, err := packetNumberFromTableRow(tablePos.Row)
	if err != nil {
		return BytesResult{}, err
	}

	var pos int
	hex := getHexWidgetToDisplay(tablePos.Row)
	if hex != nil {
		pos = hex.Position()
	}

	return BytesResult{
		PacketNum: p.Pos,
		PacketPos: pos,
	}, nil
}

// own goroutine
// startPacketNumber >= 1
func (w *BytesSearchCallbacks) SearchPacketsFrom(ifrom interface{}, istart interface{}, term search.INeedle, app gowid.IApp) {

	from := ifrom.(BytesResult)

	res := search.Result{}
	searchRes := BytesResult{}

	// True if we have packets in the current batch to search (and we aren't blocked waiting for them to load)
	curPacketNumber := from.PacketNum
	packetPos := from.PacketPos

	var resumeAt *BytesResult

	defer func() {
		if resumeAt != nil {
			w.search <- search.IntermediateResult{
				Res:      res,
				ResumeAt: *resumeAt,
			}
		} else {
			w.search <- search.IntermediateResult{
				Res: res,
			}
		}
	}()

	searchCount := 0
	pktsPerLoad := Loader.PacketsPerLoad()

Loop:
	for {
		w.DoIfStopped(func() {
			res.Interrupted = true
		})
		if res.Interrupted {
			break Loop
		}

		Loader.PsmlLoader.Lock()
		// curPacketNumber is the packet number from the pdml <packet>24</packet>. Remember there might
		// be a display filter in place.
		packetIndex, ok := Loader.PacketNumberMap[curPacketNumber]
		if !ok {
			// 1-based - packet number e.g. <packet>24</packet>
			resumeAt = &BytesResult{
				PacketNum: curPacketNumber,
			}
			Loader.PsmlLoader.Unlock()
			break
		}

		if packetIndex >= len(Loader.PsmlData()) {
			panic(nil)
		}
		Loader.PsmlLoader.Unlock()

		//======================================================================

		rowMod := (packetIndex / pktsPerLoad) * pktsPerLoad
		if ws, ok := Loader.PacketCache.Get(rowMod); ok {
			srca := ws.(pcap.CacheEntry).Pcap
			if packetIndex%pktsPerLoad < len(srca) {
				src := string(srca[packetIndex%pktsPerLoad])

				if len(src) > packetPos+1 {
					// Start at +1
					matchPos := term.Search(src[packetPos+1:])
					if matchPos != -1 {
						searchRes.PacketNum = curPacketNumber
						searchRes.PacketPos = matchPos + packetPos + 1
						searchRes.PacketRow = packetIndex
						res.Position = searchRes
						res.Success = true
						// Terminate the search
						break Loop
					}
				}
			}
		}

		//======================================================================

		packetPos = 0
		searchCount += 1

		// Returns a new object. Already takes the loader lock

		// Can this be more sophisticated?
		Loader.PsmlLoader.Lock()
		// 32, 44, 45, 134, 209,...
		curPacketNumber, ok = Loader.PacketNumberOrder[curPacketNumber]
		if !ok {
			// PacketNumberOrder is set up by the PSML loader, so if there is no next
			// value, it means we're at the end of the packets and we should loop back.
			curPacketNumber = Loader.PacketNumberOrder[0]
		}
		Loader.PsmlLoader.Unlock()

		// Go 1 past because if we loop round, we should search the original packet again
		// in case there is a hit earlier in its structure
		if searchCount > len(Loader.PacketNumberMap) {
			break Loop
		}
	}
}

func (s *BytesSearchCallbacks) SearchPacketsResult(res search.Result, app gowid.IApp) {
	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		// Do this because we might be on the same listview packet, so the change callback
		// won't run and adjust the lower view
		//
		// UPDATE - this assumes the original start position in the table is the same as
		// the one now.
		ClearProgressWidgetFor(app, SearchOwns)

		if res.Interrupted {
			return
		}

		if !res.Success {
			OpenError("Not found.", app)
			return
		}

		tableCol := 0
		bytesRes := res.Position.(BytesResult)

		curTablePos, err := packetListView.FocusXY()
		if err == nil {
			tableCol = curTablePos.Column
		}

		tableRow, err := tableRowFromPacketNumber(bytesRes.PacketNum)
		if err != nil {
			OpenError(fmt.Sprintf("Could not move to packet %d\n\n%v", bytesRes.PacketNum, err), app)
			return
		}

		packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
		// Don't continue to jump to the end
		AutoScroll = false

		//========================================

		// Callback might not run if focus position in table is the same e.g. if we find a match
		// on the same row that we started. So in that case, to expand the lower widgets, call
		// setLowerWidgets explicitly - don't rely on the focus-changed callback. And I can't
		// do a shortcut and call this if start == current because the starting position for the
		// search may not be the same as the list-view row on display - maybe the search has
		// resumed not that some extra PDML data has been loaded

		// It looks better than having the found packet be at the top of the view
		packetListView.GoToMiddle(app)

		hex := getHexWidgetToDisplay(bytesRes.PacketRow)

		if hex != nil {
			allowHexToStructRepositioning = true

			hex.SetPosition(bytesRes.PacketPos, app)
		}

		curPacketStructWidget.GoToMiddle(app)
		curStructWidgetState = curPacketStructWidget.State()
	}))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
