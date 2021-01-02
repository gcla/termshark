// Copyright 2019-2021 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

import (
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

//======================================================================

// DumpcapExt will run dumpcap first, but if it fails, run tshark. Intended as
// a special case to allow termshark -i <iface> to use dumpcap if possible,
// but if it fails (e.g. iface==randpkt), fall back to tshark. dumpcap is more
// efficient than tshark at just capturing, and will drop fewer packets, but
// tshark supports extcap interfaces.
func DumpcapExt(dumpcapBin string, tsharkBin string, args ...string) error {
	dumpcapCmd := exec.Command(dumpcapBin, args...)
	log.Infof("Starting dumpcap command %v", dumpcapCmd)
	dumpcapCmd.Stdin = os.Stdin
	dumpcapCmd.Stdout = os.Stdout
	dumpcapCmd.Stderr = os.Stderr
	if dumpcapCmd.Run() == nil {
		return nil
	}

	tsharkCmd := exec.Command(tsharkBin, args...)
	log.Infof("Retrying with dumpcap command %v", tsharkCmd)
	tsharkCmd.Stdin = os.Stdin
	tsharkCmd.Stdout = os.Stdout
	tsharkCmd.Stderr = os.Stderr
	return tsharkCmd.Run()
}
