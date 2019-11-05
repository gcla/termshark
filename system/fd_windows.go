// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build windows

package system

import (
	"fmt"
)

func MoveStdin() (int, error) {
	return -1, fmt.Errorf("MoveStdin not implemented on Windows")
}

func CloseDescriptor(fd int) {
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
