// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package hexdumper provides a widget which displays selectable hexdump-like
// output. Because it's built for termshark, it also allows styling to be
// applied to ranges of data intended to correspond to packet structure selected
// in another termshark view.
package hexdumper

import (
	"encoding/hex"
	"fmt"
	"unicode"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/palettemap"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/format"
	"github.com/gcla/termshark/v2/widgets/renderfocused"
	"github.com/gdamore/tcell/v2"
	"github.com/pkg/errors"
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

type boxedText struct {
	width int
	gowid.IWidget
}

func (h boxedText) String() string {
	return fmt.Sprintf("[hacktext %v]", h.IWidget)
}

func (h boxedText) RenderSize(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.IRenderBox {
	return gowid.RenderBox{C: h.width, R: 1}
}

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
	w                 gowid.IWidget
	data              []byte
	layers            []LayerStyler
	chrs              []boxedText
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

	res.chrs = make([]boxedText, 256)
	for i := 0; i < 256; i++ {
		if unicode.IsPrint(rune(i)) {
			// copyable text widgets need a unique ID, so gowid can tell if the current focus
			// widget (moving up the hierarchy) is the one claiming the copy
			res.chrs[i] = boxedText{
				width:   1,
				IWidget: text.NewCopyable(string(rune(i)), hexChrsId{i}, styled.UsePaletteIfSelectedForCopy{Entry: opt.PaletteIfCopying}),
			}
		}
	}

	res.w = res.Build(0)
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
	pos := w.Position()
	inhex := w.InHex()
	w.w = w.Build(pos)
	w.SetInHex(inhex, app)
	w.SetPosition(pos, app)
}

func (w *Widget) Data() []byte {
	return w.data
}

func (w *Widget) SetData(data []byte, app gowid.IApp) {
	w.data = data
	pos := w.Position()
	inhex := w.InHex()
	w.w = w.Build(pos)
	w.SetInHex(inhex, app)
	w.SetPosition(pos, app)
}

func (w *Widget) InHex() bool {
	fp := gowid.FocusPath(w.w)
	if len(fp) < 3 {
		panic(errors.WithStack(gowid.WithKVs(termshark.BadState, map[string]interface{}{"focus path": fp})))
	}
	return fp[0] == 3
}

func (w *Widget) SetInHex(val bool, app gowid.IApp) {
	fp := gowid.FocusPath(w.w)
	if len(fp) < 3 {
		panic(errors.WithStack(gowid.WithKVs(termshark.BadState, map[string]interface{}{"focus path": fp})))
	}
	if val {
		if fp[0].(int) == 3 {
			return
		}
		// from 7 to 3
		fp[0] = 3
		x := fp[2].(int)
		if x > 7 {
			fp[2] = (x * 2) - 1
		} else {
			fp[2] = x * 2
		}
	} else {
		if fp[0].(int) == 7 {
			return
		}
		// from 3 to 7
		fp[0] = 7
		x := fp[2].(int)
		if x > 14 {
			fp[2] = (x + 1) / 2
		} else {
			fp[2] = x / 2
		}
	}
	gowid.SetFocusPath(w.w, fp, app)
}

func (w *Widget) Position() int {
	fp := gowid.FocusPath(w.w)
	if len(fp) < 3 {
		panic(gowid.WithKVs(termshark.BadState, map[string]interface{}{"focus path": fp}))
	}
	if fp[0] == 3 {
		// in hex
		x := fp[2].(int)
		if x > 14 {
			return (fp[1].(int) * 16) + (x / 2) // same as below
		} else {
			return (fp[1].(int) * 16) + (x / 2)
		}
	} else {
		// in ascii
		x := fp[2].(int)
		if x > 7 {
			return (fp[1].(int) * 16) + (x - 1)
		} else {
			return (fp[1].(int) * 16) + x
		}
	}
}

func (w *Widget) SetPosition(pos int, app gowid.IApp) {
	fp := gowid.FocusPath(w.w)
	if len(fp) < 3 {
		panic(gowid.WithKVs(termshark.BadState, map[string]interface{}{"focus path": fp}))
	}
	curpos := w.Position()
	fp[1] = pos / 16
	if fp[0] == 3 {
		// from 3 to 7
		if pos%16 > 7 {
			fp[2] = ((pos % 16) * 2) + 1
		} else {
			fp[2] = (pos % 16) * 2
		}
	} else {
		if pos%16 > 7 {
			fp[2] = pos%16 + 1
		} else {
			fp[2] = pos % 16
		}
	}
	gowid.SetFocusPath(w.w, fp, app)
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
	return gowid.RenderSize(w.w, size, focus, app)
}

type privateId struct {
	*Widget
}

func (d privateId) ID() interface{} {
	return d
}

func (d privateId) Render(size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) gowid.ICanvas {
	// Skip the embedded Widget to avoid a loop
	return d.w.Render(size, focus, app)
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
		return wa.Render(size, focus, app)
	} else {
		return w.w.Render(size, focus, app)
	}
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
	if _, ok := ev.(gowid.CopyModeEvent); ok {
		if app.CopyModeClaimedAt() >= app.CopyLevel() && app.CopyModeClaimedAt() < app.CopyLevel()+len(w.Layers())+1 {
			app.CopyModeClaimedBy(w)
			res = true
		} else {
			cl := app.CopyLevel()
			app.CopyLevel(cl + len(w.Layers()) + 1) // this is how many levels hexdumper will support
			res = w.w.UserInput(ev, size, focus, app)
			app.CopyLevel(cl)

			if !res {
				app.CopyModeClaimedAt(app.CopyLevel() + len(w.Layers()))
				app.CopyModeClaimedBy(w)
			}
		}
	} else if evc, ok := ev.(gowid.CopyModeClipsEvent); ok && (app.CopyModeClaimedAt() >= app.CopyLevel() && app.CopyModeClaimedAt() < app.CopyLevel()+len(w.Layers())+1) {
		evc.Action.Collect(w.Clips(app))
		res = true
	} else {
		cur := w.Position()
		res = w.w.UserInput(ev, size, focus, app)

		if res {
			newpos := w.Position()
			if newpos != cur {
				gowid.RunWidgetCallbacks(w.Callbacks, PositionChangedCB{}, app, w)
			}
		}
	}
	return res
}

//======================================================================

func init() {
	twosp = boxedText{width: 2, IWidget: text.New("  ")}
	onesp = boxedText{width: 1, IWidget: text.New(" ")}
	dot = boxedText{width: 1, IWidget: text.New(".")}
	pad = &boxedText{width: 1, IWidget: text.New(" ")}
}

type hexChrsId struct {
	idx int
}

func (h hexChrsId) ID() interface{} {
	return h
}

var twosp boxedText
var onesp boxedText
var dot boxedText
var pad *boxedText

type IHexBuilder interface {
	Data() []byte
	Layers() []LayerStyler
	CursorUnselected() string
	CursorSelected() string
	LineNumUnselected() string
	LineNumSelected() string
}

func (w *Widget) Build(curpos int) gowid.IWidget {
	data := w.Data()
	layers := w.Layers()

	hexBytes := make([]interface{}, 0, 16*2+1)
	asciiBytes := make([]interface{}, 0, 16+1)

	fixed := gowid.RenderFixed{}

	hexRows := make([]interface{}, 0)
	asciiRows := make([]interface{}, 0)

	dlen := ((len(data) + 15) / 16) * 16 // round up to nearest chunk of 16

	layerConv := make(map[string]string)
	for _, layer := range layers {
		layerConv[layer.ColUnselected] = layer.ColSelected
	}
	layerConv[w.CursorUnselected()] = w.CursorSelected()
	layerConv[w.LineNumUnselected()] = w.LineNumSelected()

	var active gowid.ICellStyler   // for styling the hex data "41" and the ascii "A"
	var spactive gowid.ICellStyler // for styling the spaces between data e.g. "41 42"

	for i := 0; i < dlen; i++ {
		active = nil
		spactive = nil

		for _, layer := range layers {
			if i >= layer.Start && i < layer.End {
				active = gowid.MakePaletteRef(layer.ColUnselected)
			}
			if i >= layer.Start && i < layer.End-1 {
				spactive = gowid.MakePaletteRef(layer.ColUnselected)
			}
		}

		var curHex gowid.IWidget
		var curAscii gowid.IWidget
		if i >= len(data) {
			curHex = twosp
			curAscii = onesp
		} else {
			hexBtn := w.newButtonFromByte(i, data[i])

			curHex = hexBtn
			curHex = styled.NewFocus(curHex, gowid.MakePaletteRef(w.CursorUnselected()))
			if active != nil {
				curHex = styled.New(curHex, active)
			}

			asciiBtn := w.newAsciiFromByte(data[i])

			curAscii = asciiBtn
			curAscii = styled.NewFocus(curAscii, gowid.MakePaletteRef(w.CursorUnselected()))
			if active != nil {
				curAscii = styled.New(curAscii, active)
			}
		}

		hexBytes = append(hexBytes, curHex)
		asciiBytes = append(asciiBytes, curAscii)

		if (i+1)%16 == 0 {
			hexRow := columns.NewFixed(hexBytes...)
			hexRows = append(hexRows, hexRow)
			hexBytes = make([]interface{}, 0, 16*2+1)

			asciiRow := columns.NewFixed(asciiBytes...)
			asciiRows = append(asciiRows, asciiRow)
			asciiBytes = make([]interface{}, 0, 16+1)
		} else {
			// Put a blank between the buttons
			var blank gowid.IWidget = onesp
			if spactive != nil {
				blank = styled.New(blank, spactive)
			}

			hexBytes = append(hexBytes, blank)
			// separator in middle of row
			if (i+1)%16 == 8 {
				hexBytes = append(hexBytes, blank)
				asciiBytes = append(asciiBytes, blank)
			}
		}
	}

	hexPile := pile.NewWithDim(fixed, hexRows...)
	asciiPile := pile.NewWithDim(fixed, asciiRows...)

	lines := make([]interface{}, 0)

	for i := 0; i < dlen; i += 16 {
		active := false
		var txt gowid.IWidget = text.New(fmt.Sprintf(" %04x ", i))
		for _, layer := range layers {
			if i+16 >= layer.Start && i < layer.End {
				active = true
				break
			}
		}
		if active {
			txt = styled.New(txt, gowid.MakePaletteRef(w.LineNumUnselected()))
		}
		lines = append(lines, txt)
	}

	linesPile := pile.NewWithDim(fixed, lines...)

	layout := columns.NewFixed(linesPile, pad, pad, hexPile, pad, pad, pad, asciiPile)

	// When the whole widget (that fills the panel) is in focus (not down to the subwidgets yet)
	// then change the palette to use bright colors
	layoutFocused := renderfocused.New(layout)

	res := palettemap.New(
		layoutFocused,
		layerConv,
		palettemap.Map{},
	)

	return res
}

func toChar(b byte) byte {
	if b < 32 || b > 126 {
		return '.'
	}
	return b
}

type hexBytesId struct {
	idx int
}

func (h hexBytesId) ID() interface{} {
	return h
}

const hextable = "0123456789abcdef"

func (w *Widget) newButtonFromByte(idx int, v byte) *button.Widget {
	var dst [2]byte

	dst[0] = hextable[v>>4]
	dst[1] = hextable[v&0x0f]

	return button.NewBare(boxedText{
		width: 2,
		IWidget: text.NewCopyable(
			string(dst[:]),
			hexBytesId{idx},
			styled.UsePaletteIfSelectedForCopy{Entry: w.paletteIfCopying},
		),
	})
}

func (w *Widget) newAsciiFromByte(v byte) *button.Widget {
	r := rune(v)
	if r < 32 || r > 126 {
		return button.NewBare(dot)
	} else {
		return button.NewBare(w.chrs[int(r)])
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
