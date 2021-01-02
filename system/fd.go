// Copyright 2019-2021 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

package system

import (
	"syscall"
)

//======================================================================

func CloseDescriptor(fd int) {
	syscall.Close(fd)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
