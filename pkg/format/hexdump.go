// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package format implements useful string/byte formatting functions.
package format

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type Options struct {
	LeftAsciiDelimiter  string
	RightAsciiDelimiter string
}

var re *regexp.Regexp

func init() {
	re = regexp.MustCompile(`(?m)^(.{60})\|(.+?)\|$`) // do each line
}

// HexDump produces a wireshark-like hexdump, with an option to set the left and
// right delimiter used for the ascii section. This is a cheesy implementation using
// a regex to change the golang hexdump output.
func HexDump(data []byte, opts ...Options) string {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	// Output:
	// 00000000  47 6f 20 69 73 20 61 6e  20 6f 70 65 6e 20 73 6f  |Go is an open so|
	// 00000010  75 72 63 65 20 70 72 6f  67 72 61 6d 6d 69 6e 67  |urce programming|
	// 00000020  20 6c 61 6e 67 75 61 67  65 2e                    | language.|
	res := hex.Dump(data)
	res = re.ReplaceAllString(res, fmt.Sprintf(`${1}%s${2}%s`, opt.LeftAsciiDelimiter, opt.RightAsciiDelimiter))

	return strings.TrimRight(res, "\n")
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
