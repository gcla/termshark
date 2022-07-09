// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.
//

package cli

//======================================================================

type TriState struct {
	Set bool
	Val bool
}

func (b *TriState) UnmarshalFlag(value string) error {
	switch value {
	case "true", "TRUE", "t", "T", "1", "y", "Y", "yes", "Yes", "YES":
		b.Set = true
		b.Val = true
	case "false", "FALSE", "f", "F", "0", "n", "N", "no", "No", "NO":
		b.Set = true
		b.Val = false
	default:
		b.Set = false
	}
	return nil
}

func (b TriState) MarshalFlag() string {
	if b.Set {
		if b.Val {
			return "true"
		} else {
			return "false"
		}
	} else {
		return "unset"
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
