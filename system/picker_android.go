// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

import (
	"fmt"
	"os"
	"os/exec"
	"path"

	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

var NoPicker error = fmt.Errorf("No file picker available") // not running on termux
var NoTermuxApi error = fmt.Errorf("Could not launch file picker. Please install termux-api:\npkg install termux-api\n")

func PickFile() (string, error) {
	tsdir := "/data/data/com.termux/files/home"
	tsfile := "termux"
	tsabs := path.Join(tsdir, tsfile)

	if err := os.Remove(tsabs); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("Could not remove previous temporary termux file %s: %v", tsabs, err)
	}

	if _, err := exec.Command("termux-storage-get", tsabs).Output(); err != nil {
		exerr, ok := err.(*exec.Error)
		if ok && (exerr.Err == exec.ErrNotFound) {
			return "", NoTermuxApi
		} else {
			return "", fmt.Errorf("Could not select input for termshark: %v", err)
		}
	}

	if iwatcher, err := fsnotify.NewWatcher(); err != nil {
		return "", fmt.Errorf("Could not start filesystem watcher: %v\n", err)
	} else {
		defer iwatcher.Close()

		if err := iwatcher.Add(tsdir); err != nil { //&& !os.IsNotExist(err) {
			return "", fmt.Errorf("Could not set up file watcher for %s: %v\n", tsfile, err)
		}

		// Don't time it - the user might be tied up with the file picker for a while. No real way to tell...
		//tmr := time.NewTimer(time.Duration(10000) * time.Millisecond)
		//defer tmr.Close()

	Loop:
		for {
			select {
			case we := <-iwatcher.Events:
				if path.Base(we.Name) == tsfile {
					break Loop
				}

			case err := <-iwatcher.Errors:
				return "", fmt.Errorf("File watcher error for %s: %v", tsfile, err)
			}
		}

		return tsabs, nil
	}
}

func PickFileError(e string) error {
	if _, err := exec.Command("termux-toast", e).Output(); err != nil {
		exerr, ok := err.(*exec.Error)
		if ok && (exerr.Err == exec.ErrNotFound) {
			return NoTermuxApi
		} else {
			return fmt.Errorf("Error running termux-toast: %v", err)
		}
	}
	return nil
}
