// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// A demonstration of gowid's tree widget.
package pdmltree

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/tree"
	"github.com/gcla/termshark/widgets/hexdumper"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type EmptyIterator struct{}

var _ tree.IIterator = EmptyIterator{}

func (e EmptyIterator) Next() bool {
	return false
}

func (e EmptyIterator) Value() tree.IModel {
	panic(errors.New("Should not call"))
}

// pos points one head, so logically is -1 on init, but I use zero so the
// go default init makes sense.
type Iterator struct {
	tree *Model
	pos  int
}

var _ tree.IIterator = (*Iterator)(nil)

func (p *Iterator) Next() bool {
	p.pos += 1
	return (p.pos - 1) < len(p.tree.Children_)
}

func (p *Iterator) Value() tree.IModel {
	return p.tree.Children_[p.pos-1]
}

type Model struct {
	UiName    string            `xml:"-"`
	Name      string            `xml:"-"` // needed for stripping geninfp from UI
	Expanded  bool              `xml:"-"`
	Pos       int               `xml:"-"`
	Size      int               `xml:"-"`
	Hide      bool              `xml:"-"`
	Children_ []*Model          `xml:",any"`
	Content   []byte            `xml:",innerxml"` // needed for copying PDML to clipboard
	NodeName  string            `xml:"-"`
	Attrs     map[string]string `xml:"-"`
}

var _ tree.IModel = (*Model)(nil)

// This ignores the first child, "Frame 15", because its range covers the whole packet
// which results in me always including that in the layers for any position.
func (n *Model) HexLayers(pos int, includeFirst bool) []hexdumper.LayerStyler {
	res := make([]hexdumper.LayerStyler, 0)
	sidx := 1
	if includeFirst {
		sidx = 0
	}
	for _, c := range n.Children_[sidx:] {
		if c.Pos <= pos && pos < c.Pos+c.Size {
			res = append(res, hexdumper.LayerStyler{
				Start:         c.Pos,
				End:           c.Pos + c.Size,
				ColUnselected: "hex-bottom-unselected",
				ColSelected:   "hex-bottom-selected",
			})
			for _, c2 := range c.Children_ {
				if c2.Pos <= pos && pos < c2.Pos+c2.Size {
					res = append(res, hexdumper.LayerStyler{
						Start:         c2.Pos,
						End:           c2.Pos + c2.Size,
						ColUnselected: "hex-top-unselected",
						ColSelected:   "hex-top-selected",
					})
				}
			}
		}
	}
	return res
}

// Implement xml.Unmarshaler
func (n *Model) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var err error
	n.Attrs = map[string]string{}
	for _, a := range start.Attr {
		n.Attrs[a.Name.Local] = a.Value
		switch a.Name.Local {
		case "pos":
			n.Pos, err = strconv.Atoi(a.Value)
			if err != nil {
				return errors.WithStack(err)
			}
		case "size":
			n.Size, err = strconv.Atoi(a.Value)
			if err != nil {
				return errors.WithStack(err)
			}
		case "showname":
			n.UiName = a.Value
		case "show":
			if n.UiName == "" {
				n.UiName = a.Value
			}
		case "hide":
			n.Hide = (a.Value == "yes")
		case "name":
			n.Name = a.Value
		}
	}

	n.NodeName = start.Name.Local

	type pt Model
	res := d.DecodeElement((*pt)(n), &start)
	return res
}

func DecodePacket(data []byte) *Model { // nil if failure
	d := xml.NewDecoder(bytes.NewReader(data))

	var n Model
	err := d.Decode(&n)
	if err != nil {
		log.Error(err)
		return nil
	}

	tr := n.removeUnneeded()
	return tr
}

func (p *Model) removeUnneeded() *Model {
	if p.Hide {
		return nil
	}
	if p.Name == "geninfo" {
		return nil
	}
	if p.Name == "fake-field-wrapper" { // for now...
		return nil
	}
	ch := make([]*Model, 0, len(p.Children_))
	for _, c := range p.Children_ {
		nc := c.removeUnneeded()
		if nc != nil {
			ch = append(ch, nc)
		}
	}
	p.Children_ = ch
	return p
}

func (p *Model) Children() tree.IIterator {
	if p.Expanded {
		return &Iterator{
			tree: p,
		}
	} else {
		return EmptyIterator{}
	}
}

func (p *Model) HasChildren() bool {
	return len(p.Children_) > 0
}

func (p *Model) Leaf() string {
	return p.UiName
}

func (p *Model) String() string {
	return p.stringAt(1)
}

func (p *Model) stringAt(level int) string {
	x := make([]string, len(p.Children_))
	for i, t := range p.Children_ {
		//x[i] = t.(*ModelExt).String2(level + 1)
		x[i] = t.stringAt(level + 1)
	}
	for i, _ := range x {
		x[i] = strings.Repeat(" ", 2*level) + x[i]
	}
	if len(x) == 0 {
		return fmt.Sprintf("[%s]", p.UiName)
	} else {
		return fmt.Sprintf("[%s]\n%s", p.UiName, strings.Join(x, "\n"))
	}
}

//func (p *Model) Children() tree.IIterator {
//}

func (p *Model) IsCollapsed() bool {
	//return false
	return !p.Expanded
	// fp := d.FullPath()
	// if v, res := (*d.cache)[fp]; res {
	// 	return (v == collapsed)
	// } else {
	// 	return true
	// }
}

func (p *Model) SetCollapsed(app gowid.IApp, isCollapsed bool) {
	// fp := d.FullPath()
	if isCollapsed {
		p.Expanded = false
	} else {
		p.Expanded = true
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
