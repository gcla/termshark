// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/gcla/gowid"
)

//======================================================================

var re *regexp.Regexp = regexp.MustCompile(`^pos:\s*([0-9]+)`)

var FileNotOpenError = fmt.Errorf("Could not find file among descriptors")
var ParseError = fmt.Errorf("Could not match file position")

// current, max
func ProcessProgress(pid int, filename string) (int64, int64, error) {
	filename, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return -1, -1, err
	}
	fi, err := os.Stat(filename)
	if err != nil {
		return -1, -1, err
	}
	finfo, err := ioutil.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return -1, -1, err
	}
	fd := -1
	for _, f := range finfo {
		lname, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, f.Name()))
		if err == nil && lname == filename {
			fd, _ = strconv.Atoi(f.Name())
			break
		}
	}
	if fd == -1 {
		return -1, -1, gowid.WithKVs(FileNotOpenError, map[string]interface{}{"filename": filename})
	}
	info, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))

	matches := re.FindStringSubmatch(string(info))
	if len(matches) <= 1 {
		return -1, -1, gowid.WithKVs(ParseError, map[string]interface{}{"fdinfo": finfo})
	}
	pos, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return -1, -1, err
	}
	return int64(pos), fi.Size(), nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
