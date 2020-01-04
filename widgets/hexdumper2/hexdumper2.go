// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/termshark/v2/format"
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

var _ gowid.IClipboard = (*Widget)(nil)
var _ gowid.IClipboardSelected = (*Widget)(nil)

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
	return "hexdump2"
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

func (w *Widget) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	// 1<-4><3><----------(8 * 3)-1---<2<-------(8 * 3)-1-----><3><---8-->1<---8-->
	var rows int
	cols := 1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3 + 8 + 1 + 8
	if box, ok := size.(gowid.IRows); ok {
		rows = box.Rows()
	} else {
		rows = (len(w.data) + 15) / 16
	}
	return gowid.MakeRenderBox(cols, rows)
}

// 1<-4><3><----------(8 * 3)-1---<2<-------(8 * 3)-1-----><3><---8-->1<---8-->
//  0660   72 6f 72 73 2e 57 69 74  68 53 74 61 63 6b 28 67   rors.Wit hStack(g
//  0670   6f 77 69 64 2e 57 69 74  68 4b 56 73 28 4f 70 65   owid.Wit hKVs(Ope
//  0680   6e 45 72 72 6f 72 2c 20  6d 61 70 5b 73 74 72 69   nError,  map[stri
//  0690   6e 67 5d 69 6e 74 65 72  66 61 63 65 7b 7d 7b 0a   ng]inter face{}{.
//  06a0   09 09 09 09 22 64 65 73  63 72 69 70 74 6f 72 22   ...."des criptor"
//  06b0   3a 20 6e 65 77 73 74 64  69 6e 2c 0a 09 09 09 09   : newstd in,.....
//
func (w *Widget) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	var canvasRows int
	if box, ok := size.(gowid.IRows); ok {
		canvasRows = box.Rows()
	} else {
		canvasRows = (len(w.data) + 15) / 16
	}

	if canvasRows == 0 {
		return gowid.NewCanvas()
	}

	// -1 means not copy mode. 0 means the whole hexdump. 2 means the smallest layer, 1 the next biggest
	diff := -1
	if app.InCopyMode() && app.CopyModeClaimedBy().ID() == w.ID() && focus.Focus {
		diff = app.CopyModeClaimedAt() - app.CopyLevel()
	}

	cols := 1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3 + 8 + 1 + 8
	c := gowid.NewCanvasOfSize(cols, canvasRows)

	rows := gwutil.Min(canvasRows, (len(w.data)+15)/16)

	var lineNumStyle convertedStyle
	var cursorStyle convertedStyle
	var copyModeStyle convertedStyle

	if focus.Focus {
		lineNumStyle = convertStyle(gowid.MakePaletteRef(w.LineNumSelected()), app)
		cursorStyle = convertStyle(gowid.MakePaletteRef(w.CursorSelected()), app)
	} else {
		lineNumStyle = convertStyle(gowid.MakePaletteRef(w.LineNumUnselected()), app)
		cursorStyle = convertStyle(gowid.MakePaletteRef(w.CursorUnselected()), app)
	}
	copyModeStyle = convertStyle(gowid.MakePaletteRef(w.Entry), app)

	twoByteWriter := CanvasSlice{
		C: c,
	}

	asciiWriter := CanvasSlice{
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
		twoByteWriter.XOffset = 1 + 4 + 3
		asciiWriter.XOffset = 1 + 4 + 3 + ((8 * 3) - 1) + 2 + ((8 * 3) - 1) + 3

		for col := 0; col < 16; col++ {
			i = (row * 16) + col

			if i == len(w.data) {
				break Loop
			}

			active = nil
			spactive = nil

			if w.Position() == i {
				if diff != -1 {
					active = &copyModeStyle
				} else {
					active = &cursorStyle
				}
			} else {
				for j := 0; j < len(layers); j++ {
					layer = &layers[j]
					if i >= layer.Start && i < layer.End {
						if j+1 == diff {
							active = &copyModeStyle
							break
						} else {
							if focus.Focus {
								active = &layerStyles[j].s
							} else {
								active = &layerStyles[j].u
							}
						}
					}
				}
			}

			for j := 0; j < len(layers); j++ {
				layer = &layers[j]
				if i >= layer.Start && i < layer.End-1 {
					if j+1 == diff {
						spactive = &copyModeStyle
						break
					} else {
						if focus.Focus {
							spactive = &layerStyles[j].s
						} else {
							spactive = &layerStyles[j].u
						}
					}
				}
			}

			fmt.Fprintf(twoByteWriter, "%02x", w.data[i])

			if active != nil {
				styleAt(c, twoByteWriter.XOffset, twoByteWriter.YOffset, *active)
				styleAt(c, twoByteWriter.XOffset+1, twoByteWriter.YOffset, *active)
			}
			if spactive != nil {
				styleAt(c, twoByteWriter.XOffset+2, twoByteWriter.YOffset, *spactive)
				if col == 7 {
					styleAt(c, twoByteWriter.XOffset+3, twoByteWriter.YOffset, *spactive)
				}
			}

			twoByteWriter.XOffset += 3
			if col == 7 {
				twoByteWriter.XOffset += 1
			}

			ch := '.'
			r := w.data[i]
			if r >= 32 && r <= 126 {
				ch = rune(byte(r))
			}

			fmt.Fprintf(asciiWriter, "%c", ch)

			if active != nil {
				styleAt(c, asciiWriter.XOffset, asciiWriter.YOffset, *active)
			}
			if spactive != nil && col == 7 {
				styleAt(c, asciiWriter.XOffset+1, asciiWriter.YOffset, *spactive)
			}

			asciiWriter.XOffset += 1
			if col == 7 {
				asciiWriter.XOffset += 1
			}

		}

		twoByteWriter.YOffset += 1
		asciiWriter.YOffset += 1
	}

	lineNumWriter := CanvasSlice{
		C:       c,
		XOffset: 1,
	}

	for k := 0; k < rows; k++ {
		fmt.Fprintf(lineNumWriter, "%04x", k*16)

		lineNumWriter.YOffset += 1

		active := false
		for _, layer := range layers {
			if (k+1)*16 >= layer.Start && k*16 < layer.End {
				active = true
				break
			}
		}
		if active {
			for x := 0; x < 6; x++ {
				styleAt(c, x, k, lineNumStyle)
			}
		}
	}

	if diff == 0 {
		gowid.RangeOverCanvas(c, gowid.CellRangeFunc(func(cell gowid.Cell) gowid.Cell {
			return cell.WithBackgroundColor(copyModeStyle.b).WithForegroundColor(copyModeStyle.f).WithStyle(copyModeStyle.s)
		}))
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

func (w *Widget) CopyModeLevels() int {
	return len(w.layers)
}

func (w *Widget) Clips(app gowid.IApp) []gowid.ICopyResult {

	diff := app.CopyModeClaimedAt() - app.CopyLevel()
	if diff == 0 {
		return clipsForBytes(w.Data(), 0, len(w.Data()))
	} else {
		return clipsForBytes(w.Data(), w.layers[diff-1].Start, w.layers[diff-1].End)
	}
}

func (w *Widget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return gowid.CopyModeUserInput(forCopyModeWidget{forUserInputWidget{Widget: w}}, ev, size, focus, app)
}

type forCopyModeWidget struct {
	forUserInputWidget
}

// CopyModeUserInput calls UserInput() on w.SubWidget() - which is this. Then...
func (w forCopyModeWidget) SubWidget() gowid.IWidget {
	return w.forUserInputWidget
}

type forUserInputWidget struct {
	*Widget
}

// ... UserInput is sent to the hexdumper's UserInput logic.
func (w forUserInputWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	return w.Widget.realUserInput(ev, size, focus, app)
}

// Reject tab because I want it to switch views. Not intended to be transferable.
func (w *Widget) realUserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
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

// Optimization - convert the styles for use in the canvas once per call
// to Render()
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
