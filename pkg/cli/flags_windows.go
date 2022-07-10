// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package cli

import "github.com/jessevdk/go-flags"

//======================================================================

type PlatformSwitches struct{}

func (p PlatformSwitches) TtyValue() string {
	return ""
}

//======================================================================

type TailSwitch struct {
	Tail flags.Filename `value-name:"<tail-file>" long:"tail" hidden:"true" description:"Tail a file (private)."`
}

func (t TailSwitch) TailFileValue() string {
	return string(t.Tail)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
