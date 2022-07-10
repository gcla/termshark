// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
	"github.com/gcla/termshark/v2/widgets/search"
)

//======================================================================

// StructResult represents a match for a search within the packet structure. The
// result is a specific location in the packet struct model. The UI will be updated
// to show this match, expanded, when a search succeeds.
type StructResult struct {
	PacketNum int
	TreePos   tree.IPos
	Model     *pdmltree.Model
}

func (s StructResult) PacketNumber() int {
	return s.PacketNum
}

//======================================================================

// Search in the packet struct view:
//
// <proto name="ip" showname="Internet Protocol Version 4, Src: 10.215.173.1, Dst: 64.13.139.230" size="20" pos="0">
//   <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="0" show="4" value="45"/>
//   <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="0" show="20" value="45"/>
//   <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="1" show="0x00000000" value="00">
//     <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="1" show="0" value="0" unmaskedvalue="00"/>
//     <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="1" show="0" value="0" unmaskedvalue="00"/>
//   </field>
//
type StructSearchCallbacks struct {
	*commonSearchCallbacks
	*SearchStopper
	term          search.INeedle
	samePacketPos tree.IPos
	samePacket    bool // set to false if we have advanced beyond the current packet, so don't need to check list pos
	search        chan search.IntermediateResult
}

var _ tree.ISearchPred = (*StructSearchCallbacks)(nil)
var _ search.IRequestStop = (*StructSearchCallbacks)(nil)
var _ search.ICallbacks = (*StructSearchCallbacks)(nil)

func (w *StructSearchCallbacks) Reset(app gowid.IApp) {
	w.SearchStopper.Requested = false
	w.ticks = 0
}

func (w *StructSearchCallbacks) StartingPosition() (interface{}, error) {
	p, err := packetNumberFromCurrentTableRow()
	if err != nil {
		return StructResult{}, err
	}
	return StructResult{
		PacketNum: p.Pos,
	}, nil
}

// own goroutine
// startPacketNumber >= 1
func (w *StructSearchCallbacks) SearchPacketsFrom(ifrom interface{}, istart interface{}, term search.INeedle, app gowid.IApp) {

	start := istart.(StructResult)
	from := ifrom.(StructResult)

	res := search.Result{}
	searchRes := StructResult{}

	// Same position, same packet - so set flags to ensure the depth first search skips until we're
	// past the current position
	if from.PacketNum == start.PacketNum &&
		((from.TreePos == nil && start.TreePos == nil) ||
			(from.TreePos != nil && start.TreePos != nil && from.TreePos.Equal(start.TreePos))) {
		w.samePacket = true
		w.samePacketPos = curStructPosition
	}

	// True if we have packets in the current batch to search (and we aren't blocked waiting for them to load)
	curPacketNumber := from.PacketNum
	var resumeAt *StructResult

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
			resumeAt = &StructResult{
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

		// Returns a new object. Already takes the loader lock
		model := getCurrentStructModel(packetIndex)

		if model == nil {
			// This means the PDML doesn't exist in the cache. We need to request it and wait
			resumeAt = &StructResult{
				PacketNum: curPacketNumber,
			}
			break Loop
		}

		expModel := (*pdmltree.ExpandedModel)(model)

		w.term = term

		fpos := tree.DepthFirstSearch(expModel, w)
		if fpos != nil {
			searchRes.PacketNum = curPacketNumber
			searchRes.TreePos = fpos
			searchRes.Model = model
			res.Position = searchRes
			res.Success = true
			// Terminate the search
			break Loop
		}

		//======================================================================

		w.samePacket = false
		w.samePacketPos = nil
		searchCount += 1

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

func (s *StructSearchCallbacks) SearchPacketsResult(res search.Result, app gowid.IApp) {
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
		structRes := res.Position.(StructResult)

		curTablePos, err := packetListView.FocusXY()
		if err == nil {
			tableCol = curTablePos.Column
		}

		tableRow, err := tableRowFromPacketNumber(structRes.PacketNum)
		if err != nil {
			OpenError(fmt.Sprintf("Could not move to packet %d\n\n%v", structRes.PacketNum, err), app)
			return
		}

		packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
		// Don't continue to jump to the end
		AutoScroll = false

		//========================================

		curSearchPosition = structRes.TreePos.(*tree.TreePos)

		subIModel := structRes.TreePos.GetSubStructure((*pdmltree.ExpandedModel)(structRes.Model))
		expSubModel := subIModel.(*pdmltree.ExpandedModel)
		subModel := (*pdmltree.Model)(expSubModel)

		structRes.Model.MakeParentLinks(&curExpandedStructNodes)
		subModel.SetCollapsed(app, false)

		expRootModel := (*pdmltree.ExpandedModel)(structRes.Model)

		treeAtCurPos := curSearchPosition.GetSubStructure(expRootModel)
		// Save [/, tcp, tcp.srcport] - so we can apply if user moves in packet list
		curPdmlPosition = (*pdmltree.Model)(treeAtCurPos.(*pdmltree.ExpandedModel)).PathToRoot()

		//========================================

		// Callback might not run if focus position in table is the same e.g. if we find a match
		// on the same row that we started. So in that case, to expand the lower widgets, call
		// setLowerWidgets explicitly - don't rely on the focus-changed callback. And I can't
		// do a shortcut and call this if start == current because the starting position for the
		// search may not be the same as the list-view row on display - maybe the search has
		// resumed not that some extra PDML data has been loaded
		setLowerWidgets(app)

		// It looks better than having the found packet be at the top of the view
		packetListView.GoToMiddle(app)

		curPacketStructWidget.GoToMiddle(app)
		curStructWidgetState = curPacketStructWidget.State()
	}))
}

// CheckNode is provided to implement ISearchPred for the gowid tree's depth first search.
func (w *StructSearchCallbacks) CheckNode(tr tree.IModel, pos tree.IPos) bool {
	if w.samePacket {
		if w.samePacketPos != nil && !pos.GreaterThan(w.samePacketPos) {
			return false
		}
	}

	return w.term.Search(tr.Leaf()) != -1
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
