// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package noroot

import (
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/tree"
)

//======================================================================

type Walker struct {
	*tree.TreeWalker
}

func NewWalker(w *tree.TreeWalker) *Walker {
	return &Walker{
		TreeWalker: w,
	}
}

// for omitting top level node
func (f *Walker) Next(pos list.IWalkerPosition) list.IWalkerPosition {
	return tree.WalkerNext(f, pos)
}

func (f *Walker) Previous(pos list.IWalkerPosition) list.IWalkerPosition {
	fc := pos.(tree.IPos)
	pp := tree.PreviousPosition(fc, f.Tree())
	if pp.Equal(tree.NewPos()) {
		return nil
	}
	return tree.WalkerPrevious(f, pos)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
