// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package resizable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestOffset1(t *testing.T) {
	off1 := Offset{2, 4, 7}
	off1m, err := json.Marshal(off1)
	assert.NoError(t, err)
	assert.Equal(t, "{\"col1\":2,\"col2\":4,\"adjust\":7}", string(off1m))

	off2 := Offset{3, 1, 15}
	offs := []Offset{off1, off2}
	offsm, err := json.Marshal(offs)
	assert.NoError(t, err)
	assert.Equal(t, "[{\"col1\":2,\"col2\":4,\"adjust\":7},{\"col1\":3,\"col2\":1,\"adjust\":15}]", string(offsm))

	offs2 := make([]Offset, 0)
	err = json.Unmarshal(offsm, &offs2)
	assert.NoError(t, err)
	assert.Equal(t, offs, offs2)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
