// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

package pcap

import (
	"syscall"

	"github.com/pkg/errors"
)

func (c *Command) PutInNewGroupOnUnix() {
	c.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
}

func (c *Command) Kill() error {
	c.Lock()
	defer c.Unlock()
	if c.Cmd.Process == nil {
		return errors.WithStack(ProcessNotStarted{Command: c.Cmd})
	}
	return syscall.Kill(c.Cmd.Process.Pid, syscall.SIGINT)
}
