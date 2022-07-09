// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package copymodetree provides a wrapper around a tree that supports copy mode.
// It assumes the underlying tree is a termshark PDML tree and allows copying
// the PDML substructure or a serialized representation of the substructure.
package copymodetree

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/pdmltree"
)

//======================================================================

type Widget struct {
	*list.Widget
	clip gowid.IClipboardSelected
}

type ITreeAndListWalker interface {
	list.IWalker
	Decorator() tree.IDecorator
	Maker() tree.IWidgetMaker
	Tree() tree.IModel
}

// Note that tree.New() returns a *list.Widget - that's how it's implemented. So this
// uses a list widget too.
func New(l *list.Widget, clip gowid.IClipboardSelected) *Widget {
	return &Widget{
		Widget: l,
		clip:   clip,
	}
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if app.InCopyMode() && app.CopyModeClaimedBy().ID() == w.ID() && focus.Focus {
		diff := w.CopyModeLevels() - (app.CopyModeClaimedAt() - app.CopyLevel())

		walk := w.Walker().(ITreeAndListWalker)
		w.SetWalker(NewWalker(walk, walk.Focus().(tree.IPos), diff, w.clip), app)

		res := w.Widget.Render(size, focus, app)
		w.SetWalker(walk, app)
		return res
	} else {
		return w.Widget.Render(size, focus, app)
	}
}

func (w *Widget) SubWidget() gowid.IWidget {
	return w.Widget
}

func (w *Widget) CopyModeLevels() int {
	pos := w.Walker().Focus().(tree.IPos)
	return len(pos.Indices())
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return gowid.CopyModeUserInput(w, ev, size, focus, app)
}

func (w *Widget) Clips(app gowid.IApp) []gowid.ICopyResult {
	walker := w.Walker().(tree.ITreeWalker)
	pos := walker.Focus().(tree.IPos)
	lvls := w.CopyModeLevels()

	diff := lvls - (app.CopyModeClaimedAt() - app.CopyLevel())

	npos := pos
	for i := 0; i < diff; i++ {
		npos = tree.ParentPosition(npos)
	}

	tr := npos.GetSubStructure(walker.Tree())
	ptr := tr.(*pdmltree.Model)

	atts := make([]string, 0)
	atts = append(atts, string(ptr.NodeName))
	for k, v := range ptr.Attrs {
		atts = append(atts, fmt.Sprintf("%s=\"%s\"", k, v))
	}

	var tidyxmlstr string
	messyxmlstr := fmt.Sprintf("<%s>%s</%s>", strings.Join(atts, " "), ptr.Content, string(ptr.NodeName))
	buf := bytes.Buffer{}
	if termshark.IndentPdml(bytes.NewReader([]byte(messyxmlstr)), &buf) != nil {
		tidyxmlstr = messyxmlstr
	} else {
		tidyxmlstr = buf.String()
	}

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: "Selected subtree",
			Val:  ptr.String(),
		},
		gowid.CopyResult{
			Name: "Selected subtree PDML",
			Val:  tidyxmlstr,
		},
	}
}

//======================================================================

type Walker struct {
	ITreeAndListWalker
	pos  tree.IPos
	diff int
	gowid.IClipboardSelected
}

func NewWalker(walker ITreeAndListWalker, pos tree.IPos, diff int, clip gowid.IClipboardSelected) *Walker {
	return &Walker{
		ITreeAndListWalker: walker,
		pos:                pos,
		diff:               diff,
		IClipboardSelected: clip,
	}
}

func (f *Walker) At(lpos list.IWalkerPosition) gowid.IWidget {
	if lpos == nil {
		return nil
	}

	pos := lpos.(tree.IPos)
	w := tree.WidgetAt(f, pos)

	npos := f.pos
	for i := 0; i < f.diff; i++ {
		npos = tree.ParentPosition(npos)
	}

	if tree.IsSubPosition(npos, pos) {
		return f.AlterWidget(w, nil)
	} else {
		return w
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
