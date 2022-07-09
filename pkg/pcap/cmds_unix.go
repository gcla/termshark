// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !windows

package pcap

import (
	"syscall"

	"github.com/kballard/go-shellquote"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	log.Infof("Sending SIGKILL to %v: %v", c.Cmd.Process.Pid, shellquote.Join(c.Cmd.Args...))
	// The PSML tshark process doesn't reliably die with a SIGTERM - not sure why
	return syscall.Kill(-c.Cmd.Process.Pid, syscall.SIGKILL)
}
