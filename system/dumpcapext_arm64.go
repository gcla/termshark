// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !darwin
// +build !linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

//======================================================================

// DumpcapExt will run dumpcap first, but if it fails, run tshark. Intended as
// a special case to allow termshark -i <iface> to use dumpcap if possible,
// but if it fails (e.g. iface==randpkt), fall back to tshark. dumpcap is more
// efficient than tshark at just capturing, and will drop fewer packets, but
// tshark supports extcap interfaces.
func DumpcapExt(dumpcapBin string, tsharkBin string, args ...string) error {
	var err error

	dumpcapCmd := exec.Command(dumpcapBin, args...)
	fmt.Fprintf(os.Stderr, "Starting termshark's custom live capture procedure.\n")
	fmt.Fprintf(os.Stderr, "Trying dumpcap command %v\n", dumpcapCmd)
	dumpcapCmd.Stdin = os.Stdin
	dumpcapCmd.Stdout = os.Stdout
	dumpcapCmd.Stderr = os.Stderr
	if dumpcapCmd.Run() != nil {
		var tshark string
		tshark, err = exec.LookPath(tsharkBin)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Retrying with dumpcap command %v\n", append([]string{tshark}, args...))
			err = syscall.Exec(tshark, append([]string{tshark}, args...), os.Environ())
		}
	}

	return err
}
