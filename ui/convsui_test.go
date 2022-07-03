// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScan1(t *testing.T) {
	line := `127.0.0.1:47416            <-> 127.0.0.1:9191                   0         0   43549   9951808   43549   9951808     4.160565000         9.4522`

	var (
		addra      string
		addrb      string
		framesto   int
		bytesto    int
		framesfrom int
		bytesfrom  int
		frames     int
		bytes      int
		start      string
		durn       string
	)

	r := strings.NewReader(line)
	n, err := fmt.Fscanf(r, "%s <-> %s %d %d %d %d %d %d %s %s",
		&addra,
		&addrb,
		&framesto,
		&bytesto,
		&framesfrom,
		&bytesfrom,
		&frames,
		&bytes,
		&start,
		&durn,
	)

	assert.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.Equal(t, "4.160565000", start)
	assert.Equal(t, "127.0.0.1:9191", addrb)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
