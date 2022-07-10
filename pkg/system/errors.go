// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package system

//======================================================================

type NotImplementedError struct{}

var _ error = NotImplementedError{}

func (e NotImplementedError) Error() string {
	return "Feature not implemented"
}

var NotImplemented = NotImplementedError{}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
