// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.
//
// +build !windows

package termshark

import (
	"os"
	"os/signal"
	"syscall"
)

//======================================================================

func RegisterForSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGCONT, syscall.SIGUSR1, syscall.SIGUSR2)
}

func IsSigUSR1(sig os.Signal) bool {
	return IsUnixSig(sig, syscall.SIGUSR1)
}

func IsSigUSR2(sig os.Signal) bool {
	return IsUnixSig(sig, syscall.SIGUSR2)
}

func IsSigTSTP(sig os.Signal) bool {
	return IsUnixSig(sig, syscall.SIGTSTP)
}

func IsSigCont(sig os.Signal) bool {
	return IsUnixSig(sig, syscall.SIGCONT)
}

func StopMyself() error {
	return syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
