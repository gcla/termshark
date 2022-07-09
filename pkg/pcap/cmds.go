// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/summary"
	"github.com/gcla/termshark/v2/pkg/shark"
	"github.com/kballard/go-shellquote"
)

//======================================================================

type ProcessNotStarted struct {
	Command *exec.Cmd
}

var _ error = ProcessNotStarted{}

func (e ProcessNotStarted) Error() string {
	return fmt.Sprintf("Process %v [%v] not started yet", e.Command.Path, shellquote.Join(e.Command.Args...))
}

//======================================================================

type Command struct {
	sync.Mutex
	*exec.Cmd
	summaryReader *summary.Reader
	summaryWriter io.Closer
}

func (c *Command) String() string {
	c.Lock()
	defer c.Unlock()
	return fmt.Sprintf("%v %v", c.Cmd.Path, shellquote.Join(c.Cmd.Args...))
}

func (c *Command) Start() error {
	c.Lock()
	defer c.Unlock()
	pr, pw := io.Pipe()
	c.summaryWriter = pw
	c.summaryReader = summary.New(pr)
	c.Cmd.Stderr = io.MultiWriter(pw, termshark.ErrLogger("cmd", c.Path))
	c.PutInNewGroupOnUnix()
	res := c.Cmd.Start()
	return res
}

func (c *Command) Wait() error {
	err := c.Cmd.Wait()
	c.Lock()
	c.summaryWriter.Close()
	c.Unlock()
	return err
}

func (c *Command) StdoutReader() (io.ReadCloser, error) {
	c.Lock()
	defer c.Unlock()
	return c.Cmd.StdoutPipe()
}

func (c *Command) StderrSummary() []string {
	c.Lock()
	defer c.Unlock()

	return c.summaryReader.Summary()
}

func (c *Command) SetStdout(w io.Writer) {
	c.Lock()
	defer c.Unlock()
	c.Cmd.Stdout = w
}

// If stdout supports Close(), call it. If stdout is a pipe, for example,
// this can be used to have EOF appear on the reading side (e.g. tshark -T psml)
func (c *Command) Close() error {
	c.Lock()
	defer c.Unlock()
	if cl, ok := c.Cmd.Stdout.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

func (c *Command) Pid() int {
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
	Color    bool
}

func MakeCommands(decodeAs []string, args []string, pdml []string, psml []string, color bool) Commands {
	return Commands{
		DecodeAs: decodeAs,
		Args:     args,
		PdmlArgs: pdml,
		PsmlArgs: psml,
		Color:    color,
	}
}

var _ ILoaderCmds = Commands{}

func (c Commands) Iface(ifaces []string, captureFilter string, tmpfile string) IBasicCommand {
	args := make([]string, 0)
	for _, iface := range ifaces {
		args = append(args, "-i", iface)
	}
	args = append(args, "-w", tmpfile)
	if captureFilter != "" {
		args = append(args, "-f", captureFilter)
	}
	prof := profiles.ConfString("main.wireshark-profile", "")
	if prof != "" {
		args = append(args, "-C", prof)
	}
	res := &Command{
		Cmd: exec.Command(termshark.CaptureBin(), args...),
	}
	// This tells termshark to start in a special capture mode. It allows termshark
	// to run itself like this:
	//
	// termshark -i eth0 -w foo.pcap
	//
	// which will then run dumpcap and if that fails, tshark. The idea
	// is to use the most specialized/efficient capture method if that
	// works, but fall back to tshark if needed e.g. for randpkt, sshcapture, etc
	// (extcap interfaces).
	res.Cmd.Env = append(os.Environ(), "TERMSHARK_CAPTURE_MODE=1")
	res.Cmd.Stdin = os.Stdin
	res.Cmd.Stderr = os.Stderr
	res.Cmd.Stdout = os.Stdout
	return res
}

func (c Commands) Tail(tmpfile string) ITailCommand {
	args := termshark.TailCommand()
	args = append(args, tmpfile)
	return &Command{Cmd: exec.Command(args[0], args[1:]...)}
}

func (c Commands) Psml(pcap interface{}, displayFilter string) IPcapCommand {
	fifo := true
	switch pcap.(type) {
	case string:
		fifo = false
	}

	cols := shark.GetPsmlColumnFormat()
	specs := make([]string, 0, len(cols))
	for _, w := range cols {
		if !w.Hidden {
			specs = append(specs, fmt.Sprintf("\"%s\",\"%s\"", w.Name, w.Field))
		}
	}

	args := []string{
		// "-i",
		// "0",
		// "-o",
		// "0",
		//"-f", "-o", fmt.Sprintf("/tmp/foo-%d", delme), "-s", "256", "-tt",
		//termshark.TSharkBin(),
		"-T", "psml",

		// Deliberately add in a No. column as the first, no matter what the user's config says. This is
		// not added to the UI, but the loader needs it to track packet numbers when a filter is in
		// effect - so a table row (int) can be mapped to a packet number.
		"-o", fmt.Sprintf("gui.column.format:\"No.\",\"%%m\",%s", strings.Join(specs, ",")),
	}
	if !fifo {
		// read from cmdline file
		args = append(args, "-r", pcap.(string))
	} else {
		args = append(args, "-r", "-")
		args = append(args, "-l") // provide data sooner to decoder routine in termshark
	}

	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}

	for _, arg := range c.DecodeAs {
		args = append(args, "-d", arg)
	}
	if c.Color {
		args = append(args, "--color")
	}
	args = append(args, c.PsmlArgs...)
	args = append(args, c.Args...)

	prof := profiles.ConfString("main.wireshark-profile", "")
	if prof != "" {
		args = append(args, "-C", prof)
	}

	//cmd := exec.Command("strace", args...)
	cmd := exec.Command(termshark.TSharkBin(), args...)
	//cmd := exec.Command("stdbuf", args...)
	if fifo {
		cmd.Stdin = pcap.(io.Reader)
	}
	return &Command{Cmd: cmd}
}

func (c Commands) Pcap(pcap string, displayFilter string) IPcapCommand {
	// need to use stdout and -w - otherwise, tshark writes one-line text output
	args := []string{"-r", pcap, "-x"}
	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}
	args = append(args, c.Args...)
	return &Command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

func (c Commands) Pdml(pcap string, displayFilter string) IPcapCommand {
	args := []string{"-T", "pdml", "-r", pcap}
	if c.Color {
		args = append(args, "--color")
	}
	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}
	for _, arg := range c.DecodeAs {
		args = append(args, "-d", arg)
	}
	args = append(args, c.PdmlArgs...)
	args = append(args, c.Args...)

	prof := profiles.ConfString("main.wireshark-profile", "")
	if prof != "" {
		args = append(args, "-C", prof)
	}

	return &Command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
