// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/gcla/termshark"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type ProcessNotStarted struct {
	Command *exec.Cmd
}

var _ error = ProcessNotStarted{}

func (e ProcessNotStarted) Error() string {
	return fmt.Sprintf("Process %v not started yet", e.Command)
}

//======================================================================

type command struct {
	sync.Mutex
	*exec.Cmd
}

func (c *command) String() string {
	c.Lock()
	defer c.Unlock()
	return fmt.Sprintf("%v %v", c.Cmd.Path, c.Cmd.Args)
}

func (c *command) Start() error {
	c.Lock()
	defer c.Unlock()
	c.Cmd.Stderr = log.StandardLogger().Writer()
	res := c.Cmd.Start()
	return res
}

func (c *command) Wait() error {
	return c.Cmd.Wait()
}

func (c *command) StdoutPipe() (io.ReadCloser, error) {
	c.Lock()
	defer c.Unlock()
	return c.Cmd.StdoutPipe()
}

func (c *command) SetStdout(w io.Writer) {
	c.Lock()
	defer c.Unlock()
	c.Cmd.Stdout = w
}

func (c *command) Kill() error {
	if c.Cmd.Process == nil {
		return errors.WithStack(ProcessNotStarted{Command: c.Cmd})
	}
	if runtime.GOOS == "windows" {
		return c.Cmd.Process.Kill()
	} else {
		return c.Cmd.Process.Signal(os.Interrupt)
	}
}

func (c *command) Pid() int {
	c.Lock()
	defer c.Unlock()
	if c.Cmd.Process == nil {
		return -1
	}
	return c.Cmd.Process.Pid
}

//======================================================================

type Commands struct {
	DecodeAs []string
	Args     []string
	PdmlArgs []string
	PsmlArgs []string
}

func MakeCommands(decodeAs []string, args []string, pdml []string, psml []string) Commands {
	return Commands{
		DecodeAs: decodeAs,
		Args:     args,
		PdmlArgs: pdml,
		PsmlArgs: psml,
	}
}

var _ ILoaderCmds = Commands{}

func (c Commands) Iface(iface string, captureFilter string, tmpfile string) IBasicCommand {
	args := []string{"-P", "-i", iface, "-w", tmpfile}
	if captureFilter != "" {
		args = append(args, "-f", captureFilter)
	}
	return &command{Cmd: exec.Command(termshark.DumpcapBin(), args...)}
}

func (c Commands) Tail(tmpfile string) ITailCommand {
	args := termshark.TailCommand()
	args = append(args, tmpfile)
	return &command{Cmd: exec.Command(args[0], args[1:]...)}
}

func (c Commands) Psml(pcap interface{}, displayFilter string) IPcapCommand {
	fifo := true
	switch pcap.(type) {
	case string:
		fifo = false
	}

	args := []string{
		// "-i",
		// "0",
		// "-o",
		// "0",
		//"-f", "-o", fmt.Sprintf("/tmp/foo-%d", delme), "-s", "256", "-tt",
		//termshark.TSharkBin(),
		"-T", "psml",
		"-o", "gui.column.format:\"No.\",\"%m\",\"Time\",\"%t\",\"Source\",\"%s\",\"Destination\",\"%d\",\"Protocol\",\"%p\",\"Length\",\"%L\",\"Info\",\"%i\"",
	}
	if !fifo {
		// read from cmdline file
		args = append(args, "-r", pcap.(string))
	} else {
		args = append(args, "-i", "-")
		args = append(args, "-l") // provide data sooner to decoder routine in termshark
	}

	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}

	for _, arg := range c.DecodeAs {
		args = append(args, "-d", arg)
	}
	args = append(args, c.PsmlArgs...)
	args = append(args, c.Args...)

	//cmd := exec.Command("strace", args...)
	cmd := exec.Command(termshark.TSharkBin(), args...)
	//cmd := exec.Command("stdbuf", args...)
	if fifo {
		cmd.Stdin = pcap.(io.Reader)
	}
	return &command{Cmd: cmd}
}

func (c Commands) Pcap(pcap string, displayFilter string) IPcapCommand {
	// need to use stdout and -w - otherwise, tshark writes one-line text output
	args := []string{"-F", "pcap", "-r", pcap, "-w", "-"}
	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}
	args = append(args, c.Args...)
	return &command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

func (c Commands) Pdml(pcap string, displayFilter string) IPcapCommand {
	args := []string{"-T", "pdml", "-r", pcap}
	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}
	for _, arg := range c.DecodeAs {
		args = append(args, "-d", arg)
	}
	args = append(args, c.PdmlArgs...)
	args = append(args, c.Args...)
	return &command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
