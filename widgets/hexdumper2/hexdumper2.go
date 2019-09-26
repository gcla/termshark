// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package hexdumper2 provides a widget which displays selectable hexdump-like
// output. Because it's built for termshark, it also allows styling to be
// applied to ranges of data intended to correspond to packet structure selected
// in another termshark view.
package hexdumper2

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/palettemap"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/termshark/format"
	"github.com/gdamore/tcell"
)

//======================================================================

type LayerStyler struct {
	Start         int
	End           int
	ColUnselected string
	ColSelected   string
}

type PositionChangedCB struct{}

//======================================================================

type Options struct {
	StyledLayers      []LayerStyler
	CursorUnselected  string
	CursorSelected    string
	LineNumUnselected string
	LineNumSelected   string
	PaletteIfCopying  string
}

type Widget struct {
	data              []byte
	layers            []LayerStyler
	position          int
	cursorUnselected  string
	cursorSelected    string
	lineNumUnselected string
	lineNumSelected   string
	paletteIfCopying  string
	gowid.AddressProvidesID
	styled.UsePaletteIfSelectedForCopy
	Callbacks *gowid.Callbacks
	gowid.IsSelectable
}

var _ gowid.IWidget = (*Widget)(nil)
var _ gowid.IIdentityWidget = (*Widget)(nil)

//var _ gowid.IClipboard = (*Widget)(nil)
//var _ gowid.IClipboardSelected = (*Widget)(nil)

func New(data []byte, opts ...Options) *Widget {

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	res := &Widget{
		data:                        data,
		layers:                      opt.StyledLayers,
		cursorUnselected:            opt.CursorUnselected,
		cursorSelected:              opt.CursorSelected,
		lineNumUnselected:           opt.LineNumUnselected,
		lineNumSelected:             opt.LineNumSelected,
		paletteIfCopying:            opt.PaletteIfCopying,
		UsePaletteIfSelectedForCopy: styled.UsePaletteIfSelectedForCopy{Entry: opt.PaletteIfCopying},
		Callbacks:                   gowid.NewCallbacks(),
	}

	return res
}

func (w *Widget) OnPositionChanged(f gowid.IWidgetChangedCallback) {
	gowid.AddWidgetCallback(w.Callbacks, PositionChangedCB{}, f)
}

func (w *Widget) RemoveOnPositionChanged(f gowid.IIdentity) {
	gowid.RemoveWidgetCallback(w.Callbacks, PositionChangedCB{}, f)
}

func (w *Widget) String() string {
	return "hexdump"
}

func (w *Widget) CursorUnselected() string {
	return w.cursorUnselected
}
func (w *Widget) CursorSelected() string {
	return w.cursorSelected
}
func (w *Widget) LineNumUnselected() string {
	return w.lineNumUnselected
}
func (w *Widget) LineNumSelected() string {
	return w.lineNumSelected
}

func (w *Widget) Layers() []LayerStyler {
	return w.layers
}

func (w *Widget) SetLayers(layers []LayerStyler, app gowid.IApp) {
	w.layers = layers
}

func (w *Widget) Data() []byte {
	return w.data
}

func (w *Widget) SetData(data []byte, app gowid.IApp) {
	w.data = data
}

func (w *Widget) InHex() bool {
	// gcla later todo
	return true
}

func (w *Widget) SetInHex(val bool, app gowid.IApp) {
	// gcla later todo
}

func (w *Widget) Position() int {
	return w.position
}

func (w *Widget) SetPosition(pos int, app gowid.IApp) {
	curpos := w.Position()
	w.position = pos
	if curpos != pos {
		gowid.RunWidgetCallbacks(w.Callbacks, PositionChangedCB{}, app, w)
	}
}

type viewSwitchFn func(ev *tcell.EventKey) bool

type viewSwitch struct {
	w  *Widget
	fn viewSwitchFn
}

// Compatible with appkeys.Widget
func (v viewSwitch) SwitchView(ev *tcell.EventKey, app gowid.IApp) bool {
	if v.fn(ev) {
		v.w.SetInHex(!v.w.InHex(), app)
		return true
	}
	return false
}

func (w *Widget) OnKey(fn viewSwitchFn) viewSwitch {
	return viewSwitch{
		w:  w,
		fn: fn,
	}
}

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	// 1<-4><3><----------(8 * 3)-1---<2<-------(8 * 3)-1-----><3><---8-->1<---8-->
	return gowid.MakeRenderBox(1+4+3+((8*3)-1)+2+((8*3)-1)+3+8+1+8, (len(w.data)+15)/16)
}

type privateId struct {
	*Widget
}

func (d privateId) ID() interface{} {
	return d
}

func (d privateId) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	// Skip the embedded Widget to avoid a loop
	return gowid.Render(d.Widget, size, focus, app)
}

func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	if app.InCopyMode() && app.CopyModeClaimedBy().ID() == w.ID() && focus.Focus {

		var wa gowid.IWidget
		diff := app.CopyModeClaimedAt() - app.CopyLevel()
		if diff == 0 {
			wa = w.AlterWidget(privateId{w}, app) // whole hexdump
		} else {
			layerConv := make(map[string]string)
			for i := diff - 1; i < len(w.Layers()); i++ {
				layerConv[w.layers[i].ColSelected] = "copy-mode" // only right layers
			}
			wa = palettemap.New(privateId{w}, layerConv, layerConv)
		}
		return gowid.Render(wa, size, focus, app)
	} else {
		return w.realRender(size, focus, app)
	}
}

type convertedStyle struct {
	f gowid.TCellColor
	b gowid.TCellColor
	s gowid.StyleAttrs
}

type convertedLayer struct {
	u convertedStyle
	s convertedStyle
}

func convertStyle(style gowid.ICellStyler, app gowid.IApp) convertedStyle {
	f, b, s := style.GetStyle(app)
	f1 := gowid.IColorToTCell(f, gowid.ColorNone, app.GetColorMode())
	b1 := gowid.IColorToTCell(b, gowid.ColorNone, app.GetColorMode())
	return convertedStyle{
		f: f1,
		b: b1,
		s: s,
	}
}

// 1<-4><3><----------(8 * 3)-1---<2<-------(8 * 3)-1-----><3><---8-->1<---8-->
//  0660   72 6f 72 73 2e 57 69 74  68 53 74 61 63 6b 28 67   rors.Wit hStack(g
//  0670   6f 77 69 64 2e 57 69 74  68 4b 56 73 28 4f 70 65   owid.Wit hKVs(Ope
//  0680   6e 45 72 72 6f 72 2c 20  6d 61 70 5b 73 74 72 69   nError,  map[stri
//  0690   6e 67 5d 69 6e 74 65 72  66 61 63 65 7b 7d 7b 0a   ng]inter face{}{.
//  06a0   09 09 09 09 22 64 65 73  63 72 69 70 74 6f 72 22   ...."des criptor"
//  06b0   3a 20 6e 65 77 73 74 64  69 6e 2c 0a 09 09 09 09   : newstd in,.....
//
func (w *Widget) realRender(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	rows := (len(w.data) + 15) / 16 // 1 -> 1, 16 -> 1, 17 -> 2
	if rows == 0 {
		return gowid.NewCanvas()
	}
	cols := 1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3 + 8 + 1 + 8
	c := gowid.NewCanvasOfSize(cols, rows)

	var lineNumStyle convertedStyle
	var cursorStyle convertedStyle

	if focus.Focus {
		lineNumStyle = convertStyle(gowid.MakePaletteRef(w.LineNumSelected()), app)
		cursorStyle = convertStyle(gowid.MakePaletteRef(w.CursorSelected()), app)
	} else {
		lineNumStyle = convertStyle(gowid.MakePaletteRef(w.LineNumUnselected()), app)
		cursorStyle = convertStyle(gowid.MakePaletteRef(w.CursorUnselected()), app)
	}

	chslice := CanvasSlice{
		C: c,
	}

	ahslice := CanvasSlice{
		C: c,
	}

	var active *convertedStyle   // for styling the hex data "41" and the ascii "A"
	var spactive *convertedStyle // for styling the spaces between data e.g. "41 42"

	// nil
	// [1, 5]
	// [2, 3]
	//
	// Deliberately add a blank layer at the beginning for index 0
	layers := w.Layers()
	var layer *LayerStyler

	layerStyles := make([]convertedLayer, len(layers))
	for i := 0; i < len(layers); i++ {
		layerStyles[i].u = convertStyle(gowid.MakePaletteRef(layers[i].ColUnselected), app)
		layerStyles[i].s = convertStyle(gowid.MakePaletteRef(layers[i].ColSelected), app)
	}

	var i int
Loop:
	for row := 0; row < rows; row++ {
		chslice.XOffset = 1 + 4 + 3
		ahslice.XOffset = 1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3

		for col := 0; col < 16; col++ {
			i = (row * 16) + col

			if i == len(w.data) {
				break Loop
			}

			active = nil
			spactive = nil

			for j := 0; j < len(layers); j++ {
				layer = &layers[j]
				if i >= layer.Start && i < layer.End {
					if focus.Focus {
						active = &layerStyles[j].s
					} else {
						active = &layerStyles[j].u
					}
				}
				if i >= layer.Start && i < layer.End-1 {
					if focus.Focus {
						spactive = &layerStyles[j].s
					} else {
						spactive = &layerStyles[j].u
					}
				}
			}

			fmt.Fprintf(chslice, "%02x", w.data[i])

			if w.Position() == i {
				styleAt(c, chslice.XOffset, chslice.YOffset, cursorStyle)
				styleAt(c, chslice.XOffset+1, chslice.YOffset, cursorStyle)
			} else if active != nil {
				styleAt(c, chslice.XOffset, chslice.YOffset, *active)
				styleAt(c, chslice.XOffset+1, chslice.YOffset, *active)
			}
			if spactive != nil {
				styleAt(c, chslice.XOffset+2, chslice.YOffset, *spactive)
				if col == 7 {
					styleAt(c, chslice.XOffset+3, chslice.YOffset, *spactive)
				}
			}

			chslice.XOffset += 3
			if col == 7 {
				chslice.XOffset += 1
			}

			ch := '.'
			r := w.data[i]
			if r >= 32 && r <= 126 {
				ch = rune(byte(r))
			}

			fmt.Fprintf(ahslice, "%c", ch)

			if w.Position() == i {
				styleAt(c, ahslice.XOffset, ahslice.YOffset, cursorStyle)
			} else if active != nil {
				styleAt(c, ahslice.XOffset, ahslice.YOffset, *active)
			}
			if spactive != nil && col == 7 {
				styleAt(c, ahslice.XOffset+1, ahslice.YOffset, *spactive)
			}

			ahslice.XOffset += 1
			if col == 7 {
				ahslice.XOffset += 1
			}

		}

		chslice.YOffset += 1
		ahslice.YOffset += 1
	}

	hhslice := CanvasSlice{
		C:       c,
		XOffset: 1,
	}

	for k := 0; k < len(w.data); k += 16 {
		fmt.Fprintf(hhslice, "%04x", k)

		hhslice.YOffset += 1

		active := false
		for _, layer := range layers {
			if k+16 >= layer.Start && k < layer.End {
				active = true
				break
			}
		}
		if active {
			for x := 0; x < 6; x++ {
				styleAt(c, x, k/16, lineNumStyle)
			}
		}
	}

	return c
}

func clipsForBytes(data []byte, start int, end int) []gowid.ICopyResult {
	dump := hex.Dump(data[start:end])
	dump2 := format.MakeEscapedString(data[start:end])
	dump3 := format.MakePrintableString(data[start:end])
	dump4 := format.MakeHexStream(data[start:end])

	return []gowid.ICopyResult{
		gowid.CopyResult{
			Name: fmt.Sprintf("Copy bytes %d-%d as hex + ascii", start, end),
			Val:  dump,
		},
		gowid.CopyResult{
			Name: fmt.Sprintf("Copy bytes %d-%d as escaped string", start, end),
			Val:  dump2,
		},
		gowid.CopyResult{
			Name: fmt.Sprintf("Copy bytes %d-%d as printable string", start, end),
			Val:  dump3,
		},
		gowid.CopyResult{
			Name: fmt.Sprintf("Copy bytes %d-%d as hex stream", start, end),
			Val:  dump4,
		},
	}
}

func (w *Widget) Clips(app gowid.IApp) []gowid.ICopyResult {

	diff := app.CopyModeClaimedAt() - app.CopyLevel()
	if diff == 0 {
		return clipsForBytes(w.Data(), 0, len(w.Data()))
	} else {
		return clipsForBytes(w.Data(), w.layers[diff-1].Start, w.layers[diff-1].End)
	}
}

// Reject tab because I want it to switch views. Not intended to be transferable.
func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	res := false

	scrollDown := false
	scrollUp := false

	switch ev := ev.(type) {
	case *tcell.EventKey:

		switch ev.Key() {
		case tcell.KeyRight, tcell.KeyCtrlF:
			//res = Scroll(w, 1, w.Wrap(), app)
			pos := w.Position()
			if pos < len(w.data) {
				w.SetPosition(pos+1, app)
				res = true
			}
		case tcell.KeyLeft, tcell.KeyCtrlB:
			pos := w.Position()
			if pos > 0 {
				w.SetPosition(pos-1, app)
				res = true
			}
		case tcell.KeyDown, tcell.KeyCtrlN:
			scrollDown = true
		case tcell.KeyUp, tcell.KeyCtrlP:
			scrollUp = true
		}

	case *tcell.EventMouse:
		switch ev.Buttons() {
		case tcell.WheelDown:
			scrollDown = true
		case tcell.WheelUp:
			scrollUp = true
		case tcell.Button1:
			xp := -1
			mx, my := ev.Position()
			// 1<-4><3><----------(8 * 3)-1---<2<-------(8 * 3)-1-----><3><---8-->1<---8-->
			//  0660   72 6f 72 73 2e 57 69 74  68 53 74 61 63 6b 28 67   rors.Wit hStack(g
			//  0670   6f 77 69 64 2e 57 69 74  68 4b 56 73 28 4f 70 65   owid.Wit hKVs(Ope
			switch {
			case mx >= 1+4+3 && mx < 1+4+3+((8*3)-1):
				xp = (mx - (1 + 4 + 3)) / 3
			case mx >= 1+4+3+((8*3)-1)+2 && mx < 1+4+3+((8*3)-1)+2+((8*3)-1):
				xp = ((mx - (1 + 4 + 3 + ((8 * 3) - 1) + 2)) / 3) + 8
			case mx >= 1+4+3+((8*3)-1)+2+((8*3)-1)+3 && mx < 1+4+3+((8*3)-1)+2+((8*3)-1)+3+8:
				xp = mx - (1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3)
			case mx >= 1+4+3+((8*3)-1)+2+((8*3)-1)+3+8+1 && mx < 1+4+3+((8*3)-1)+2+((8*3)-1)+3+8+1+8:
				xp = mx - (1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3 + 8 + 1) + 8
			}
			if xp != -1 {
				pos := (my * 16) + xp
				if pos < len(w.data) {
					w.SetPosition(pos, app)
					res = true
				}
			}

		}
	}

	if scrollDown {
		pos := w.Position()
		if pos+16 < len(w.data) {
			w.SetPosition(pos+16, app)
			res = true
		}
	} else if scrollUp {
		pos := w.Position()
		if pos-16 >= 0 {
			w.SetPosition(pos-16, app)
			res = true
		}
	}

	return res
}

//======================================================================

type CanvasSlice struct {
	C       *gowid.Canvas
	XOffset int
	YOffset int
}

var _ io.Writer = CanvasSlice{}
var _ gowid.IRangeOverCanvas = CanvasSlice{}

func NewCanvasSlice(c *gowid.Canvas, xoff, yoff int) CanvasSlice {
	res := CanvasSlice{
		C:       c,
		XOffset: xoff,
		YOffset: yoff,
	}
	return res
}

func (c CanvasSlice) Write(p []byte) (n int, err error) {
	return gowid.WriteToCanvas(c, p)
}

func (c CanvasSlice) ImplementsWidgetDimension() {}

func (c CanvasSlice) BoxColumns() int {
	return c.C.BoxColumns()
}

func (c CanvasSlice) BoxRows() int {
	return c.C.BoxRows()
}

func (c CanvasSlice) CellAt(col, row int) gowid.Cell {
	return c.C.CellAt(col+c.XOffset, row+c.YOffset)
}

func (c CanvasSlice) SetCellAt(col, row int, cell gowid.Cell) {
	c.C.SetCellAt(col+c.XOffset, row+c.YOffset, cell)
}

func styleAt(canvas gowid.ICanvas, col int, row int, st convertedStyle) {
	c := canvas.CellAt(col, row)
	c = c.MergeDisplayAttrsUnder(c.WithForegroundColor(st.f).WithBackgroundColor(st.b).WithStyle(st.s))
	canvas.SetCellAt(col, row, c)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
