// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.
//
// +build !windows

package cli

//======================================================================

// Embedded in the CLI options struct.
type PlatformSwitches struct {
	Tty string `long:"tty" description:"Display the UI on this terminal." value-name:"<tty>"`
}

func (p PlatformSwitches) TtyValue() string {
	return p.Tty
}

//======================================================================

type TailSwitch struct{}

func (t TailSwitch) TailFileValue() string {
	return ""
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
