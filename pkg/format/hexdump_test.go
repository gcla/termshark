// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================

func TestHexDump1(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{
			"Go is an open source programming language.",
			"00000000  47 6f 20 69 73 20 61 6e  20 6f 70 65 6e 20 73 6f  QGo is an open so\n" +
				"00000010  75 72 63 65 20 70 72 6f  67 72 61 6d 6d 69 6e 67  Qurce programming\n" +
				"00000020  20 6c 61 6e 67 75 61 67  65 2e                    Q language.",
		},
	}

	for _, test := range tests {
		assert.Equal(t, true, (HexDump([]byte(test.in), Options{
			LeftAsciiDelimiter: "Q",
		}) == test.out))
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
