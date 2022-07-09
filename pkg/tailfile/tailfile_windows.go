// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package tailfile

import (
	"os"

	"github.com/gcla/tail"
)

//======================================================================

func Tail(file string) error {
	t, err := tail.TailFile(file, tail.Config{
		Follow: true,
		ReOpen: true,
		Poll:   true,
		Logger: tail.DiscardingLogger,
	})
	if err != nil {
		return err
	}

	for chunk := range t.Bytes {
		os.Stdout.Write([]byte(chunk.Text))
	}
	return nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
