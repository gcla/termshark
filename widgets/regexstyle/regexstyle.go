// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package regexstyle provides a widget that highlights the content of its subwidget according to a regular
// expression. The widget is also given an occurrence parameter which determines which instance of the regex
// match is highlighted, or if -1 is supplied, all instances are highlighted. The widget currently wraps a
// text widget only since it depends on that widget being able to clone its content.
package regexstyle

import (
	"regexp"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/text"
)

//======================================================================

// This is the type of subwidget supported by regexstyle
type ContentWidget interface {
	gowid.IWidget
	Content() text.IContent
	SetContent(gowid.IApp, text.IContent)
}

type Widget struct {
	ContentWidget
	Highlight
}

type Highlight struct {
	Re    *regexp.Regexp
	Occ   int
	Style gowid.ICellStyler
}

func New(w ContentWidget, hl Highlight) *Widget {
	res := &Widget{
		ContentWidget: w,
		Highlight:     hl,
	}
	return res
}

func (w *Widget) SetRegexOccurrence(i int) {
	w.Occ = i
}

func (w *Widget) SetRegex(re *regexp.Regexp) {
	w.Re = re
}

func (w *Widget) RegexMatches() int {
	return len(w.regexMatches(w.Content()))
}

func (w *Widget) regexMatches(content text.IContent) [][]int {
	if w.Re == nil || w.Style == nil {
		return [][]int{}
	}

	runes := make([]rune, 0, content.Length())

	for i := 0; i < w.Content().Length(); i++ {
		runes = append(runes, w.Content().ChrAt(i))
	}

	return w.Re.FindAllStringIndex(string(runes), -1)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if w.Re == nil || w.Style == nil {
		return w.ContentWidget.Render(size, focus, app)
	}

	// save orig so it can be restored before end of render
	content := w.Content()
	if clonableContent, ok := content.(text.ICloneContent); !ok {
		return w.ContentWidget.Render(size, focus, app)
	} else {
		dup := clonableContent.Clone()

		if textContent, ok := content.(*text.Content); !ok {
			return w.ContentWidget.Render(size, focus, app)
		} else {

			indices := w.regexMatches(content)

			if len(indices) == 0 {
				return w.ContentWidget.Render(size, focus, app)
			}

			for i := 0; i < len(indices); i++ {
				if w.Occ == i || w.Occ == -1 {
					for j := indices[i][0]; j < indices[i][1]; j++ {
						(*textContent)[j].Attr = w.Style
					}
				}
			}

			// Let the underlying text widget layout the text in the way it's configured to
			// (line breaks, justification, etc)
			canvas := w.ContentWidget.Render(size, focus, app)

			w.SetContent(app, dup)

			return canvas
		}
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
