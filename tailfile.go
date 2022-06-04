// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

//+build !windows

package termshark

import (
	"os"
	"os/exec"
)

//======================================================================

func TailFile(file string) error {
	cmd := exec.Command("tail", "-f", file)
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
