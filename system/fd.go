// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

package system

import (
	"os"
	"syscall"
)

//======================================================================

func CloseDescriptor(fd int) {
	syscall.Close(fd)
}

func FileRegularOrLink(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}

	return fi.Mode().IsRegular() || (fi.Mode()&os.ModeSymlink != 0)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
