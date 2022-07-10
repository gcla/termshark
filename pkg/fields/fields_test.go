// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package fields

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestFields1(t *testing.T) {

	fields := New()
	err := fields.InitNoCache()
	assert.NoError(t, err)

	m1, ok := fields.ser.Fields.(map[string]interface{})["tcp"]
	assert.Equal(t, true, ok)

	m2, ok := m1.(map[string]interface{})["port"]
	assert.Equal(t, true, ok)

	assert.IsType(t, Field{}, m2)
	assert.Equal(t, m2.(Field).Type, FT_UINT16)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
