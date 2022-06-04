// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package hexdumper

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestDump1(t *testing.T) {
	widget1 := New([]byte("abcdefghijklmnopqrstuvwxyz0123456789 abcdefghijklmnopqrstuvwxyz0123456789"))
	//stylers: []LayerStyler{styler},
	canvas1 := widget1.Render(gowid.RenderFlowWith{C: 80}, gowid.NotSelected, gwtest.D)
	log.Infof("Canvas1 is %s", canvas1.String())
	assert.Equal(t, 5, canvas1.BoxRows())
}

func TestDump2(t *testing.T) {
	widget1 := New([]byte(""))
	canvas2 := widget1.Render(gowid.RenderFlowWith{C: 60}, gowid.NotSelected, gwtest.D)
	log.Infof("Canvas2 is %s", canvas2.String())
	assert.Equal(t, 1, canvas2.BoxRows())
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
