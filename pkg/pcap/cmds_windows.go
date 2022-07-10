// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import "github.com/pkg/errors"

func (c *Command) PutInNewGroupOnUnix() {}

func (c *Command) Kill() error {
	c.Lock()
	defer c.Unlock()
	if c.Cmd.Process == nil {
		return errors.WithStack(ProcessNotStarted{Command: c.Cmd})
	}
	return c.Cmd.Process.Kill()
}
