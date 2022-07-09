// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package format implements useful string/byte formatting functions.
package format

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

func MakePrintableString(data []byte) string {
	var buffer bytes.Buffer
	for i := 0; i < len(data); i++ {
		if unicode.IsPrint(rune(data[i])) {
			buffer.WriteString(string(rune(data[i])))
		}
	}
	return buffer.String()
}

func MakePrintableStringWithNewlines(data []byte) string {
	var buffer bytes.Buffer
	for i := 0; i < len(data); i++ {
		if (data[i] >= 32 && data[i] < 127) || data[i] == '\n' {
			buffer.WriteString(string(rune(data[i])))
		} else {
			buffer.WriteRune('.')
		}
	}
	return buffer.String()
}

func MakeEscapedString(data []byte) string {
	res := make([]string, 0)
	var buffer bytes.Buffer
	for i := 0; i < len(data); i++ {
		buffer.WriteString(fmt.Sprintf("\\x%02x", data[i]))
		if i%16 == 16-1 || i+1 == len(data) {
			res = append(res, fmt.Sprintf("\"%s\"", buffer.String()))
			buffer.Reset()
		}
	}
	return strings.Join(res, " \\\n")
}

func MakeHexStream(data []byte) string {
	var buffer bytes.Buffer
	for i := 0; i < len(data); i++ {
		buffer.WriteString(fmt.Sprintf("%02x", data[i]))
	}
	return buffer.String()
}

var hexRe = regexp.MustCompile(`\\x[0-9a-fA-F][0-9a-fA-F]`)

// TranslateHexCodes will change instances of "\x41" in the input to the
// byte 'A' in the output, passing through other characters. This is a small
// subset of strconv.Unquote() for wireshark PSML data.
func TranslateHexCodes(s []byte) []byte {
	return hexRe.ReplaceAllFunc(s, func(m []byte) []byte {
		r, err := hex.DecodeString(string(m[2:]))
		if err != nil {
			panic(err)
		}
		return []byte{r[0]}
	})
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
