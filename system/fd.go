// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

package system

import (
	"os"
	"syscall"

	"github.com/gcla/gowid"
	"github.com/pkg/errors"
)

//======================================================================

type FSError string

func (e FSError) Error() string {
	return string(e)
}

var (
	DupError   FSError = "Error duplicating descriptor."
	CloseError FSError = "Error closing file descriptor."
	OpenError  FSError = "Error opening for read."

	_ error = DupError
	_ error = CloseError
	_ error = OpenError
)

func MoveStdin() (int, error) {
	newinputfd, err := syscall.Dup(int(os.Stdin.Fd()))
	if err != nil {
		err = errors.WithStack(gowid.WithKVs(DupError, map[string]interface{}{
			"descriptor": os.Stdin.Fd(),
			"detail":     err,
		}))
		return -1, err
	}
	err = syscall.Close(int(os.Stdin.Fd()))
	if err != nil {
		err = errors.WithStack(gowid.WithKVs(CloseError, map[string]interface{}{
			"descriptor": os.Stdin.Fd(),
			"detail":     err,
		}))
		return -1, err
	}
	newstdin, err := syscall.Open("/dev/tty", syscall.O_RDONLY, 0)
	if err != nil {
		err = errors.WithStack(gowid.WithKVs(OpenError, map[string]interface{}{
			"name":   "/dev/tty",
			"detail": err,
		}))
		return -1, err
	}
	if newstdin != 0 {
		err = syscall.Dup2(newstdin, 0)
		if err != nil {
			err = errors.WithStack(gowid.WithKVs(DupError, map[string]interface{}{
				"descriptor": newstdin,
				"detail":     err,
			}))
			return -1, err
		}
		err = syscall.Close(newstdin)
		if err != nil {
			err = errors.WithStack(gowid.WithKVs(OpenError, map[string]interface{}{
				"descriptor": newstdin,
				"detail":     err,
			}))
			return -1, err
		}
	}

	return newinputfd, nil
}

func CloseDescriptor(fd int) {
	syscall.Close(fd)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
