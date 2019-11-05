// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.
//
// +build !windows

package cli

//======================================================================

// Embedded in the CLI options struct.
type PlatformSpecific struct {
	Tty string `long:"tty" description:"Display the UI on this terminal." value-name:"<tty>"`
}

func TtySwitchValue(opts *Termshark) string {
	return opts.Tty
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
