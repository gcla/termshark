// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// +build !android

package system

import (
	"fmt"
)

var NoPicker error = fmt.Errorf("No file picker available")

func PickFile() (string, error) {
	return "", NoPicker
}

func PickFileError(e string) error {
	fmt.Println(e)
	return nil
}
