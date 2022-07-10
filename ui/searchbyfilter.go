// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/gcla/termshark/v2/pkg/pcap"
	"github.com/gcla/termshark/v2/widgets/search"
	log "github.com/sirupsen/logrus"
	"gitlab.com/jonas.jasas/condchan"
)

//======================================================================

// FilterResult represents a match via a display filter search. This is no more
// specific than a packet/frame number to jump to.
type FilterResult struct {
	PacketNum int
}

func (s FilterResult) PacketNumber() int {
	return s.PacketNum
}

//======================================================================

// Search via a display filter
//
type FilterSearchCallbacks struct {
	*commonSearchCallbacks
	curSearchTerm string
	searchMap     map[string]*filterSearchState
	mapLock       sync.Mutex
	searchResChan chan search.IntermediateResult
}

type filterSearchState struct {
	cmd      pcap.IPcapCommand
	ctx      context.Context // cancelling this cancels the dependent contexts - used to close whole loader.
	cancelFn context.CancelFunc
	pcapInfo os.FileInfo

	// To protect below:
	cc *condchan.CondChan

	// State covered by cc and ccMtx
	first         int         // first packet found; from here, jump into nextMap
	nextMap       map[int]int // map from actual packet row <packet>12</packet> to pos in unsorted table
	finished      bool        // true if filter search process and mapping goroutine have done their work.
	interrupted   bool
	errorFromUser error
}

func newFilterSearchState(filename string, cmd pcap.IPcapCommand) (*filterSearchState, error) {
	ctx, cancelFn := context.WithCancel(Loader.Context())

	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	res := &filterSearchState{
		cmd:      cmd,
		nextMap:  make(map[int]int),
		ctx:      ctx,
		cancelFn: cancelFn,
		pcapInfo: info,
	}
	res.cc = condchan.New(&sync.Mutex{})
	return res, nil
}

var _ search.IRequestStop = (*FilterSearchCallbacks)(nil)
var _ search.ICallbacks = (*FilterSearchCallbacks)(nil)

func NewFilterSearchCallbacks(
	callbacks *commonSearchCallbacks,
	searchCh chan search.IntermediateResult) *FilterSearchCallbacks {
	res := &FilterSearchCallbacks{
		commonSearchCallbacks: callbacks,
		searchResChan:         searchCh,
		searchMap:             make(map[string]*filterSearchState),
	}
	return res
}

func (w *FilterSearchCallbacks) Reset(app gowid.IApp) {
}

func (w *FilterSearchCallbacks) StartingPosition() (interface{}, error) {
	p, err := packetNumberFromCurrentTableRow()
	if err != nil {
		return FilterResult{}, err
	}

	return FilterResult{PacketNum: p.Pos}, nil
}

func (w *FilterSearchCallbacks) RequestStop(app gowid.IApp) {
	w.mapLock.Lock()
	defer w.mapLock.Unlock()
	if mpval, ok := w.searchMap[w.curSearchTerm]; ok {
		mpval.cc.L.Lock()
		mpval.cancelFn()
		if !mpval.finished {
			mpval.interrupted = true
		}
		mpval.cc.L.Unlock()
	}
}

// Assumes lock is held
func (w *FilterSearchCallbacks) searchStartedFor(search string) bool {
	_, ok := w.searchMap[search]
	return ok
}

// startPacketNumber >= 1
func (w *FilterSearchCallbacks) SearchPacketsFrom(ifrom interface{}, istart interface{}, term search.INeedle, app gowid.IApp) {

	// We are in control if these types by agreement with searchalg.go
	from := ifrom.(FilterResult)

	searchFor := term.(fmt.Stringer).String()

	if Loader.DisplayFilter() != "" {
		searchFor = fmt.Sprintf("(%s) && (%s)", Loader.DisplayFilter(), searchFor)
	}

	var mpval *filterSearchState
	killCurrent := false
	filename := getPsmlFile()

	var saveMap map[int]int

	w.mapLock.Lock()
	if w.searchStartedFor(searchFor) {
		// The mpval is guaranteed created here
		mpval = w.searchMap[searchFor]

		fi, err := os.Stat(filename)
		if err != nil {
			w.OnError(fmt.Errorf("Could not open pcap: %w", err), app)
		} else {
			if fi.Size() != mpval.pcapInfo.Size() {
				killCurrent = true
			}
		}

		if killCurrent {
			mpval.cancelFn()
			// We don't need to throw away the existing data - because the pcap will only
			// grow, meaning any search matches in the smaller pcap will match in the larger - I think!
			saveMap = mpval.nextMap
			delete(w.searchMap, searchFor)
			mpval = nil
		}
	}

	if mpval == nil {

		var err error
		psmlCmd := makePsmlCommand(filename, searchFor)
		mpval, err = newFilterSearchState(filename, psmlCmd)
		if err != nil {
			w.OnError(fmt.Errorf("Could not open pcap: %w", err), app)
		} else {

			if saveMap != nil {
				mpval.nextMap = saveMap
			}

			w.curSearchTerm = searchFor
			w.searchMap[searchFor] = mpval

			termshark.TrackedGo(func() {
				// When this returns, the process has finished running, and if it started, Wait()
				// has been called.
				err := w.runProcess(mpval.ctx, psmlCmd, app, func(prev int, cur int) {
					mpval.cc.L.Lock()

					if mpval.first == 0 {
						mpval.first = cur
					}

					if prev != 0 {
						if cur == 0 {
							// Only make last link at end, when all are loaded - so we don't cycle round
							// when the load is still ongoing, misleading the user
							mpval.nextMap[prev] = mpval.first
						} else {
							mpval.nextMap[prev] = cur
						}
					}

					mpval.cc.L.Unlock()
					mpval.cc.Broadcast()
				})

				mpval.cc.L.Lock()
				mpval.cancelFn()
				mpval.finished = true
				mpval.errorFromUser = err
				mpval.cc.L.Unlock()
			}, Goroutinewg)
		}
	}
	w.mapLock.Unlock()

	// Note - mpval might be nil here, if we couldn't open the pcap file

	res := search.Result{}

	//==================================================

	// We'll definitely return a result of some kind - found or nothing
	defer func() {
		w.searchResChan <- search.IntermediateResult{
			Res: res,
		}
	}()

	// Calculate result from this call, or wait for result. This is pretty lame and would benefit
	// from some better data structures e.g. some sort of interval map.
	getClosest := func() int {
		closest := -1
		distance := -1
		if from.PacketNum < mpval.first {
			closest = mpval.first
		} else {
			for k := range mpval.nextMap {
				if distance == -1 || (k-from.PacketNum < distance && k > from.PacketNum) {
					distance = k - from.PacketNum
					closest = k
				}
			}
			if closest == -1 {
				// If nothing in the map, use the first value which is stored here. If that
				// is zero, it means nothing has been found yet...
				closest = mpval.first
			}
		}
		return closest
	}

	if mpval == nil {
		return
	}

	// Find the closest matching packet from the current position in the table
	mpval.cc.L.Lock()
	defer mpval.cc.L.Unlock()

Loop:
	for {
		res.ErrorForUser = mpval.errorFromUser
		res.Interrupted = mpval.interrupted

		if next, ok := mpval.nextMap[from.PacketNum]; ok {
			res.Position = FilterResult{
				PacketNum: next,
			}
			res.Success = true
			break Loop
		} else {
			closest := getClosest()
			if closest != 0 {
				res.Position = FilterResult{
					PacketNum: closest,
				}
				res.Success = true
				break Loop
			} else if mpval.finished {
				// No hits and load finished - return search failed
				break Loop
			}
		}

		if !mpval.finished {
			mpval.cc.Select(func(c <-chan struct{}) { // Waiting with select
				// Either of these two channels mean we should proceed. The first
				// means that some search state has changed - maybe a new result,
				// maybe a cancellation, maybe the end of the process execution. The
				// second means something else interrupted - e.g. user hit the stop
				// button.
				select {
				case <-c:
				case <-mpval.ctx.Done():
				}
			})
		}
	}
}

func (s *FilterSearchCallbacks) SearchPacketsResult(res search.Result, app gowid.IApp) {
	app.Run(gowid.RunFunction(func(app gowid.IApp) {

		s.ticks = 0

		// Do this because we might be on the same listview packet, so the change callback
		// won't run and adjust the lower view
		//
		// UPDATE - this assumes the original start position in the table is the same as
		// the one now.
		ClearProgressWidgetFor(app, SearchOwns)

		if res.Interrupted {
			// If interrupted, delete all state. Then the next time Find is hit, it will all be
			// kicked off again from a clean slate
			s.mapLock.Lock()
			delete(s.searchMap, s.curSearchTerm)
			s.curSearchTerm = ""
			s.mapLock.Unlock()
			return
		}

		if !res.Success {
			if res.ErrorForUser != nil {
				OpenError(res.ErrorForUser.Error(), app)
			} else {
				OpenError("Not found.", app)
			}
			return
		}

		filterRes := res.Position.(FilterResult)

		tableCol := 0
		curTablePos, err := packetListView.FocusXY()
		if err == nil {
			tableCol = curTablePos.Column
		}

		tableRow, err := tableRowFromPacketNumber(filterRes.PacketNum)
		if err != nil {
			OpenError(fmt.Sprintf("Could not move to packet %d\n\n%v", filterRes.PacketNum, err), app)
			return
		}

		packetListView.SetFocusXY(app, table.Coords{Column: tableCol, Row: tableRow})
		// Don't continue to jump to the end
		AutoScroll = false

		// Callback might not run if focus position in table is the same e.g. if we find a match
		// on the same row that we started. So in that case, to expand the lower widgets, call
		// setLowerWidgets explicitly - don't rely on the focus-changed callback. And I can't
		// do a shortcut and call this if start == current because the starting position for the
		// search may not be the same as the list-view row on display - maybe the search has
		// resumed not that some extra PDML data has been loaded

		setLowerWidgets(app)

		// It looks better than having the found packet be at the top of the view
		packetListView.GoToMiddle(app)
	}))
}

// makePsmlCommand generates the tshark command to run to generate the sequence of results from search,
// according to the filter value.
func makePsmlCommand(filename string, displayFilter string) pcap.IPcapCommand {
	args := []string{
		"-T", "psml",
		"-o", fmt.Sprintf("gui.column.format:\"No.\",\"%%m\""),
	}
	// read from cmdline file
	args = append(args, "-r", filename)

	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}

	psmlArgs := profiles.ConfStringSlice("main.psml-args", []string{})
	tsharkArgs := profiles.ConfStringSlice("main.tshark-args", []string{})

	args = append(args, psmlArgs...)
	args = append(args, tsharkArgs...)

	cmd := exec.Command(termshark.TSharkBin(), args...)

	return &pcap.Command{Cmd: cmd}
}

func getPsmlFile() string {
	res := Loader.InterfaceFile() // Might be loading from interface or fifo
	if res == "" {
		res = Loader.PcapPsml.(string)
	}
	return res
}

func (w *FilterSearchCallbacks) runProcess(ctx context.Context, psmlCmd pcap.IPcapCommand, app gowid.IApp, addRes func(int, int)) (err error) {

	var psmlOut io.ReadCloser
	psmlOut, err = psmlCmd.StdoutReader()
	if err != nil {
		return
	}

	err = psmlCmd.Start()
	if err != nil {
		return
	}

	defer func() {
		err := psmlCmd.Wait()
		if err != nil {
			w.OnError(fmt.Errorf("Error waiting: %w", err), app)
		}
	}()

	termshark.TrackedGo(func() {
		// Do this in a goroutine because if we try in the for loop below, we might block endlessly
		// waiting for d.Token() to return, even though the context is cancelled
		select {
		case <-ctx.Done():
			psmlCmd.Kill()
		}
	}, Goroutinewg)

	log.Infof("Started PSML search command %v with pid %d", psmlCmd, psmlCmd.Pid())

	d := xml.NewDecoder(psmlOut)

	// <packet>
	// <section>1</section>
	// </packet>

	var curPsml []string
	var pidx int
	ppidx := 0 // the previous packet number read; 0 means no packet. I can use 0 because
	// the psml I read will start at packet 1 so - map[0] => 1st packet
	ready := false
	empty := true
	structure := false
	addLast := true

	defer func() {
		if addLast {
			addRes(ppidx, 0)
		}
	}()

	for {
		err = ctx.Err()
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			addLast = false
			break
		}
		var tok xml.Token
		tok, err = d.Token()
		if err != nil {
			if err != io.EOF {
				err = fmt.Errorf("Could not read PSML data: %v", err)
				addLast = false
			} else {
				// Don't show IO errors to the user
				err = nil
			}
			break
		}
		switch tok := tok.(type) {
		case xml.EndElement:
			switch tok.Name.Local {
			case "structure":
				structure = false
			case "packet":
				// Track the mapping of packet number <section>12</section> to position
				// in the table e.g. 5th element. This is so that I can jump to the correct
				// row with marks even if a filter is currently applied.
				pidx, err = strconv.Atoi(curPsml[0])
				if err != nil {
					break
				}
				addRes(ppidx, pidx)
				ppidx = pidx

			case "section":
				ready = false
				// Means we got </section> without any char data i.e. empty <section>
				if empty {
					curPsml = append(curPsml, "")
				}
			}
		case xml.StartElement:
			switch tok.Name.Local {
			case "structure":
				structure = true
			case "packet":
				curPsml = make([]string, 0, 10)
			case "section":
				ready = true
				empty = true
			}
		case xml.CharData:
			if ready {
				if !structure {
					curPsml = append(curPsml, string(format.TranslateHexCodes(tok)))
					empty = false
				}
			}
		}
	}

	return
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
