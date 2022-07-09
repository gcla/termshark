// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package summary

import (
	"bufio"
	"io"
	"sync"

	"github.com/gcla/termshark/v2"
)

//======================================================================

// Reader maintains the first two and last two lines read from a source io.Reader.
// At any point, the Summary() function can be called to extract a summary of
// what's been read so far. I'm using this to create a summary of the stderr of
// a termshark command.
type Reader struct {
	source      io.Reader
	first       *string
	second      *string
	penultimate *string
	last        *string
	num         int
	lock        sync.Mutex
}

func New(source io.Reader) *Reader {
	res := &Reader{
		source: source,
	}

	termshark.TrackedGo(func() {
		res.start()
	}, Goroutinewg)

	return res
}

func (h *Reader) Summary() []string {
	h.lock.Lock()
	defer h.lock.Unlock()

	res := make([]string, 0, 5)
	if h.num >= 1 {
		res = append(res, *h.first)
	}
	if h.num >= 2 {
		res = append(res, *h.second)
	}
	if h.num >= 5 {
		res = append(res, "...")
	}
	if h.num >= 4 {
		res = append(res, *h.penultimate)
	}
	if h.num >= 3 {
		res = append(res, *h.last)
	}

	return res
}

func (h *Reader) start() {
	scanner := bufio.NewScanner(h.source)
	for scanner.Scan() {
		line := scanner.Text()
		h.lock.Lock()
		h.num += 1
		if h.first == nil {
			h.first = &line
		} else if h.second == nil {
			h.second = &line
		}

		h.penultimate = h.last
		h.last = &line
		h.lock.Unlock()
	}
}

//======================================================================

// This is a debugging aid - I use it to ensure goroutines stop as expected. If they don't
// the main program will hang at termination.
var Goroutinewg *sync.WaitGroup

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
