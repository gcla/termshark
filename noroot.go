// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/tree"
)

//======================================================================

type NoRootWalker struct {
	*tree.TreeWalker
}

func NewNoRootWalker(w *tree.TreeWalker) *NoRootWalker {
	return &NoRootWalker{
		TreeWalker: w,
	}
}

// for omitting top level node
func (f *NoRootWalker) Next(pos list.IWalkerPosition) list.IWalkerPosition {
	return tree.WalkerNext(f, pos)
}

func (f *NoRootWalker) Previous(pos list.IWalkerPosition) list.IWalkerPosition {
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
