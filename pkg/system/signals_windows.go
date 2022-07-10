// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

import (
	"os"
	"os/signal"

	"github.com/gcla/gowid"
)

//======================================================================

func RegisterForSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func IsSigUSR1(sig os.Signal) bool {
	return false
}

func IsSigUSR2(sig os.Signal) bool {
	return false
}

func IsSigTSTP(sig os.Signal) bool {
	return false
}

func IsSigCont(sig os.Signal) bool {
	return false
}

func StopMyself() error {
	return gowid.WithKVs(NotImplemented, map[string]interface{}{"feature": "SIGSTOP"})
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
