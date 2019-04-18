// Copyright 2019 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package termshark

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestFields1(t *testing.T) {

	fields := NewFields()
	err := fields.Init()
	assert.NoError(t, err)

	m1, ok := fields.fields.M["tcp"]
	assert.Equal(t, true, ok)

	m2, ok := m1.M["port"]
	assert.Equal(t, true, ok)

	_, ok = m2.M["foo"]
	assert.Equal(t, false, ok)

}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
