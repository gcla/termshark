// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"github.com/gcla/gowid/gwutil"
)

//======================================================================

type averageTracker struct {
	count uint64
	total uint64
}

func (a averageTracker) average() gwutil.IntOption {
	if a.count == 0 {
		return gwutil.NoneInt()
	}
	return gwutil.SomeInt(int(a.total / a.count))
}

func (a *averageTracker) update(more int) {
	a.count += 1
	a.total += uint64(more)
}

type maxTracker struct {
	cur int
}

func (a maxTracker) max() int {
	return a.cur
}

func (a *maxTracker) update(candidate int) {
	if candidate > a.cur {
		a.cur = candidate
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
