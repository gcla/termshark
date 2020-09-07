// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// package theme provides utilities for customizing the styling of termshark.
package theme

import (
	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type Layer int

const (
	Foreground Layer = 0
	Background Layer = iota
)

// MakeColorSafe extends gowid's MakeColorSafe function, prefering to interpret
// its string argument as a toml file config key lookup first; if this fails, then
// fall back to gowid.MakeColorSafe, which will then read colors as urwid color names,
// #-prefixed hex digits, grayscales, etc.
func MakeColorSafe(s string, l Layer) (gowid.Color, error) {
	loops := 10
	cur := s
	for {
		next := termshark.ConfString(cur, "")
		if next != "" {
			cur = next
		} else {
			next := termshark.ConfStringSlice(cur, []string{})
			if len(next) != 2 {
				break
			} else {
				cur = next[l]
			}
		}
		loops -= 1
		if loops == 0 {
			break
		}
	}
	col, err := gowid.MakeColorSafe(cur)
	if err == nil {
		return gowid.Color{IColor: col, Id: s}, nil
	}
	col, err = gowid.MakeColorSafe(s)
	if err != nil {
		log.Infof("Could not understand configured theme color '%s'", s)
	}
	return col, err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
