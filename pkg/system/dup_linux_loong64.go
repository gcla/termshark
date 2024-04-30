// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

import "syscall"

func Dup2(fd int, fd2 int) error {
	return syscall.Dup3(fd, fd2, 0)
}
