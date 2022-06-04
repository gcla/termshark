// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package trackfocus

import (
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gcla/gowid/widgets/text"
	"github.com/stretchr/testify/assert"
)

func TestTrackFocus1(t *testing.T) {
	tw := text.New("foobar")
	ftw := New(tw)

	c := ftw.Render(gowid.RenderFixed{}, gowid.Focused, gwtest.D)

	cbran := false
	ftw.OnFocusLost(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w gowid.IWidget) {
		cbran = true
	}))

	assert.Equal(t, "foobar", c.String())

	ftw.Render(gowid.RenderFixed{}, gowid.Focused, gwtest.D)
	assert.Equal(t, false, cbran)

	ftw.Render(gowid.RenderFixed{}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, true, cbran)

	cbran = false
	ftw.Render(gowid.RenderFixed{}, gowid.Focused, gwtest.D)
	assert.Equal(t, false, cbran)

	ftw.RemoveOnFocusLost(gowid.CallbackID{"cb"})
	ftw.Render(gowid.RenderFixed{}, gowid.NotSelected, gwtest.D)
	assert.Equal(t, false, cbran)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
