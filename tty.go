// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.
//
// +build !windows

package termshark

import (
	"os"
	"syscall"

	"github.com/pkg/term/termios"
)

//======================================================================

type TerminalSignals struct {
	tiosp syscall.Termios
	out   *os.File
	set   bool
}

func (t *TerminalSignals) IsSet() bool {
	return t.set
}

func (t *TerminalSignals) Restore() {
	if t.out != nil {
		fd := uintptr(t.out.Fd())
		termios.Tcsetattr(fd, termios.TCSANOW, &t.tiosp)

		t.out.Close()
		t.out = nil
	}
	t.set = false
}

func (t *TerminalSignals) Set() error {
	var e error
	var newtios syscall.Termios
	var fd uintptr

	outtty := "/dev/tty"

	gwtty := os.Getenv("GOWID_TTY")
	if gwtty != "" {
		outtty = gwtty
	}

	if t.out, e = os.OpenFile(outtty, os.O_WRONLY, 0); e != nil {
		goto failed
	}

	fd = uintptr(t.out.Fd())

	if e = termios.Tcgetattr(fd, &t.tiosp); e != nil {
		goto failed
	}

	newtios = t.tiosp
	newtios.Lflag |= syscall.ISIG

	// Enable ctrl-z for suspending the foreground process group via the
	// line discipline. Ctrl-c and Ctrl-\ are not handled, so the terminal
	// app will receive these keypresses.
	newtios.Cc[syscall.VSUSP] = 032
	newtios.Cc[syscall.VINTR] = 0
	newtios.Cc[syscall.VQUIT] = 0

	if e = termios.Tcsetattr(fd, termios.TCSANOW, &newtios); e != nil {
		goto failed
	}

	t.set = true

	return nil

failed:
	if t.out != nil {
		t.out.Close()
		t.out = nil
	}
	return e
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
