// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package number

import (
	"testing"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gdamore/tcell/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

//======================================================================

func evclick(x, y int) *tcell.EventMouse {
	return tcell.NewEventMouse(x, y, tcell.Button1, 0)
}

func evunclick(x, y int) *tcell.EventMouse {
	return tcell.NewEventMouse(x, y, tcell.ButtonNone, 0)
}

func TestNumber1(t *testing.T) {
	v := 2

	w := New(Options{
		Value: v,
	})
	sz := gowid.RenderFixed{}

	c1 := w.Render(sz, gowid.NotSelected, gwtest.D)
	log.Infof("Canvas is %s", c1.String())
	// "0 [^v]"
	assert.Equal(t, 1, c1.BoxRows())

	clickat := func(x, y int) {
		w.UserInput(evclick(x, y), sz, gowid.Focused, gwtest.D)
		gwtest.D.SetLastMouseState(gowid.MouseState{true, false, false, time.Now()})
		w.UserInput(evunclick(x, y), sz, gowid.Focused, gwtest.D)
		gwtest.D.SetLastMouseState(gowid.MouseState{false, false, false, time.Now()})
	}

	clickat(2, 0)
	assert.Equal(t, v, w.Value)

	clickat(3, 0)
	assert.Equal(t, v+1, w.Value)

	clickat(4, 0)
	clickat(4, 0)
	assert.Equal(t, v+1-2, w.Value)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
