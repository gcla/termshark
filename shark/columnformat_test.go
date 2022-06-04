// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package shark

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestCF1(t *testing.T) {

	fields := &ColumnsFromTshark{}
	err := fields.InitNoCache()
	assert.NoError(t, err)

	cfmap := make(map[string]PsmlColumnSpec)
	for _, f := range fields.fields {
		fmt.Printf("GCLA: adding %v\n", f)
		cfmap[f.Field.Token] = f
	}

	m1, ok := cfmap["%At"]
	assert.Equal(t, true, ok)
	assert.Equal(t, "Absolute time", m1.Name)

	m2, ok := cfmap["%rs"]
	assert.Equal(t, true, ok)
	assert.Equal(t, "Src addr (resolved)", m2.Name)
}
