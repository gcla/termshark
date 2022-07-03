// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package rossshark provides a widget that draws a hi-tech shark fin over the
// background and allows it to move across the screen. I hope this is faithful
// to Ross Jacobs' vision :-)
package rossshark

import (
	"math/rand"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
)

//======================================================================

var maskF []string
var maskB = []string{
	"00000000000000000000000000111111111",
	"00000000000000000000011111111111110",
	"00000000000000000111111111111111100",
	"00000000000000111111111111111111000",
	"00000000000011111111111111111110000",
	"00000000001111111111111111111110000",
	"00000000111111111111111111111100000",
	"00000001111111111111111111111100000",
	"00000011111111111111111111111100000",
	"00000111111111111111111111111100000",
	"00001111111111111111111111111100000",
	"00011111111111111111111111111100000",
	"00111111111111111111111111111100000",
	"01111111111111111111111111111100000",
	"01111111111111111111111111111110000",
	"11111111111111111111111111111110000",
	"11111111111111111111111111111111000",
	"11111111111111111111111111111111100",
}

func init() {
	maskF = make([]string, 0, len(maskB))
	for _, line := range maskB {
		maskF = append(maskF, reverseString(line))
	}
}

type Direction int

const (
	Backward Direction = 0
	Forward  Direction = iota
)

type Widget struct {
	gowid.IWidget
	Dir     Direction
	active  bool
	xOffset int
	mask    [][]string
	backg   []string
	ticker  *time.Ticker
}

var _ gowid.IWidget = (*Widget)(nil)

func New(w gowid.IWidget) *Widget {
	backg := make([]string, 0, 48)
	for i := 0; i < cap(backg); i++ {
		backg = append(backg, randomString(110))
	}
	res := &Widget{
		IWidget: w,
		mask:    [][]string{maskB, maskF},
		backg:   backg,
		xOffset: 100000,
	}
	return res
}

func (w *Widget) Advance() {
	switch w.Dir {
	case Backward:
		w.xOffset -= 1
		if w.xOffset <= -len(w.mask[0]) {
			w.xOffset = 100000 // big enough
		}
	case Forward:
		w.xOffset += 1
	}
}

func (w *Widget) Activate() {
	w.ticker = time.NewTicker(time.Duration(150) * time.Millisecond)
}

func (w *Widget) Deactivate() {
	w.ticker = nil
}

func (w *Widget) Active() bool {
	return w.ticker != nil
}

func (w *Widget) C() <-chan time.Time {
	return w.ticker.C
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	c := w.IWidget.Render(size, focus, app)
	if w.Active() {
		// Adjust here to account for the fact the screen can be resized
		if w.xOffset >= c.BoxColumns() {
			switch w.Dir {
			case Backward:
				w.xOffset = c.BoxColumns() - 1
			case Forward:
				w.xOffset = -len(w.mask[0])
			}
		}
		mask := w.mask[w.Dir]
		yOffset := c.BoxRows()/2 - len(mask)/2 // in the middle
		for y, sy := gwutil.Max(0, yOffset), gwutil.Max(0, -yOffset); y < c.BoxRows() && sy < len(mask); y, sy = y+1, sy+1 {
			for x, sx := gwutil.Max(0, w.xOffset), gwutil.Max(0, -w.xOffset); x < c.BoxColumns() && sx < len(mask[0]); x, sx = x+1, sx+1 {
				if mask[sy][sx] == '1' {
					cell := c.CellAt(x, y)
					r := w.backg[y%len(w.backg)][x%len(w.backg[0])]
					c.SetCellAt(x, y, cell.WithRune(rune(r)))
				}
			}
		}
	}
	return c
}

//======================================================================

// Use charset [a-f0-9] to mirror tshark -x/xxd hex output
const charset = "abcdef0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func randomString(length int) string {
	return randomStringWithCharset(length, charset)
}

// Plagiarized from https://stackoverflow.com/a/4965535 - the most straightforward answer
func reverseString(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
