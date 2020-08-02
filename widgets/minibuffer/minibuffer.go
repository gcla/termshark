// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package minibuffer todo
package minibuffer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/dialog"
	"github.com/gcla/gowid/widgets/edit"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/isselected"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/overlay"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2/widgets/keepselected"
	"github.com/gdamore/tcell"
)

//======================================================================

// Widget represents a termshark-specific "minibuffer" widget, expected to be opened
// as a dialog near the bottom of the screen. It allows the user to type commands and
// supports tab completion and listing completions.
type Widget struct {
	*dialog.Widget
	compl      *holder.Widget
	selections *list.Widget
	ed         *edit.Widget
	pl         *pile.Widget
	showAll    bool // true if the user hits tab with nothing in the minibuffer. I don't
	// want to display all completions if the buffer is empty because it fills the screen
	// and looks ugly. So this is a hack to allow the completions to be displayed
	// via the tab key
	actions map[string]IAction
}

var _ gowid.IWidget = (*Widget)(nil)

var nullw *null.Widget
var wordExp *regexp.Regexp

func init() {
	nullw = null.New()
	wordExp = regexp.MustCompile(`( *)((?:")[^"]*(?:")|[^\s]*)`)
}

// IAction represents a command that can be run in the minibuffer e.g. "set". It
// can decide whether or not to show in the list of completions e.g. if the user
// types "s".
type IAction interface {
	Run(gowid.IApp, ...string) error // nil means success
	Arguments([]string) []IArg
	OfferCompletion() bool
}

// IArg represents an argument to a minibuffer command e.g. "dark-mode" in the
// command "set dark-mode on".
type IArg interface {
	OfferCompletion() bool
	Completions() []string
}

type partial struct {
	word string
	line string
	cp   int
}

// keysWidget redirects printable characters to the edit widget (the lower), but navigational
// commands like up/down will control the selection widget.
type keysWidget struct {
	*pile.Widget
	top    gowid.IWidget
	bottom gowid.IWidget
	outer  *Widget
}

var _ gowid.IWidget = (*keysWidget)(nil)

func (w *keysWidget) UserInput(ev interface{}, size gowid.IRenderSize, focus gowid.Selector, app gowid.IApp) bool {
	res := false
	switch ev := ev.(type) {
	case *tcell.EventKey:
		switch ev.Key() {
		case tcell.KeyRune:
			res = w.bottom.UserInput(ev, size, focus, app)
		case tcell.KeyDown, tcell.KeyCtrlN, tcell.KeyUp, tcell.KeyCtrlP:
			res = w.top.UserInput(ev, size, focus, app)
		case tcell.KeyTAB, tcell.KeyEnter:
			w.outer.handleSelection(ev.Key() == tcell.KeyEnter, app)
			res = true
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if w.outer.ed.Text() == "" {
				if w.outer.IsOpen() {
					w.outer.Close(app)
				}
				res = true
			}
		}
	}
	if !res {
		res = w.Widget.UserInput(ev, size, focus, app)
	}
	w.Widget.SetFocus(app, 1)
	return res
}

func New() *Widget {
	res := &Widget{}
	editW := edit.New(edit.Options{
		Caption: ":",
	})
	editW.OnTextSet(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, ew gowid.IWidget) {
		res.updateCompletions(app)
	})))

	// If the cursor pos changes, we might not be displaying the right set of completions
	editW.OnCursorPosSet(gowid.MakeWidgetCallback("cb", gowid.WidgetChangedFunction(func(app gowid.IApp, ew gowid.IWidget) {
		res.updateCompletions(app)
	})))

	top := holder.New(nullw)
	bottom := hpadding.New(editW, gowid.HAlignLeft{}, gowid.RenderFlow{})

	bufferW := pile.New(
		[]gowid.IContainerWidget{
			&gowid.ContainerWidget{
				IWidget: top,
				D:       gowid.RenderFlow{},
			},
			&gowid.ContainerWidget{
				IWidget: bottom,
				D:       gowid.RenderFlow{},
			},
		},
		pile.Options{
			StartRow: 1,
		},
	)

	keys := &keysWidget{
		Widget: bufferW,
		top:    top,
		bottom: bottom,
		outer:  res,
	}

	*res = Widget{
		Widget: dialog.New(
			keys,
			dialog.Options{
				Buttons:         []dialog.Button{},
				NoShadow:        true,
				NoFrame:         false,
				BackgroundStyle: gowid.MakePaletteRef("minibuffer"),
				ButtonStyle:     gowid.MakePaletteRef("minibuffer-buttons"),
			},
		),
		compl:   top,
		ed:      editW,
		pl:      bufferW,
		actions: make(map[string]IAction),
	}
	return res
}

func (w *Widget) handleSelection(keyIsEnter bool, app gowid.IApp) {
	// Break edit text up into "words"

	// gcla later todo - need to check it's not nil
	selectedIdx := 0
	if w.selections != nil {
		selectedIdx = int(w.selections.Walker().Focus().(list.ListPos))
	}

	wordMatchesS := wordExp.FindAllStringSubmatch(w.ed.Text(), -1)
	words := make([]string, 0, len(wordMatchesS))
	for _, m := range wordMatchesS {
		if m[2] != "" {
			words = append(words, strings.TrimPrefix(strings.TrimSuffix(m[2], "\""), "\"")) // make a list of the words in the minibuffer
		}
	}

	switch {
	// how many words are in the edit box
	case len(words) > 1: // a command with args, so command itself must be provided in full.
		partials := w.getPartialsCompletions(false, app)
		switch len(partials) {
		//					case 1:
		case 0:
			// "load /tmp/foo" and []  - just run what the user typed if the key was enter
			if act, ok := w.actions[words[0]]; ok && keyIsEnter {
				err := act.Run(app, words...)
				if err == nil {
					// Run the command, let it handle errors
					if w.IsOpen() {
						w.Close(app)
					}
				}
			}
		default:
			// if the last word exactly equals the one selected in the partials, just run on enter
			if words[len(words)-1] == partials[selectedIdx].word && keyIsEnter {
				// "load /tmp/foo.pcap" and ["/tmp/foo.pcap"]
				if act, ok := w.actions[words[0]]; ok {
					err := act.Run(app, words...)
					if err == nil {
						// Run the command, let it handle errors
						if w.IsOpen() {
							w.Close(app)
						}
					}
				}
			} else {
				// Otherwise, tab complete
				//
				// "load /tmp/foo" and ["/tmp/foo2.pcap", "/tmp/foo.pcap"]
				//                                         ^^^^^^^^^^^^^
				w.ed.SetText(partials[selectedIdx].line, app)
				w.ed.SetCursorPos(partials[selectedIdx].cp, app)
			}
			//default:
		}

	case len(words) == 1: // command itself may be partially provided. If there is only
		// one way for the command to be completed, allow it to be run.
		partials := w.getPartialsCompletions(false, app)
		switch len(partials) {
		case 0:
			if act, ok := w.actions[words[0]]; ok && keyIsEnter {
				err := act.Run(app, words...)
				if err == nil {
					// Run the command, let it handle errors
					if w.IsOpen() {
						w.Close(app)
					}
				}
			}
		default:
			if words[len(words)-1] == partials[selectedIdx].word && keyIsEnter {
				act := w.actions[partials[selectedIdx].word]
				if len(act.Arguments([]string{})) == 0 {
					err := w.actions[partials[selectedIdx].word].Run(app, partials[selectedIdx].word)
					if err == nil {
						if w.IsOpen() {
							w.Close(app)
						}
					}
				}
			} else {
				w.ed.SetText(partials[selectedIdx].line, app)
				w.ed.SetCursorPos(partials[selectedIdx].cp, app)
			}
		}

	default:
		if w.selections == nil {
			w.showAll = true
			w.updateCompletions(app)
		} else if keyIsEnter {
			// if the selections are being displayed and enter is hit, complete that selection
			partials := w.getPartialsCompletions(true, app)
			w.ed.SetText(partials[selectedIdx].line, app)
			w.ed.SetCursorPos(partials[selectedIdx].cp, app)
		}
	}
}

// Not thread-safe, manage via App perhaps
func (w *Widget) Register(name string, action IAction) {
	w.actions[name] = action
}

func (w *Widget) getPartialsCompletions(checkOffer bool, app gowid.IApp) []partial {
	txt := w.ed.Text()
	partials := make([]partial, 0)

	// e.g. "demo false" -> [[0 4 0 0 0 4] [4 10 4 5 5 10]]
	wordMatches := wordExp.FindAllStringSubmatchIndex(txt, -1)
	wordMatchesS := wordExp.FindAllStringSubmatch(txt, -1)

	wordIdx := 0
	wordStart := 0
	wordEnd := 0
	cp := w.ed.CursorPos() // for : prompt?
	for mIdx, wordMatch := range wordMatches {
		wordIdx = mIdx
		wordStart = wordMatch[4]
		wordEnd = wordMatch[5]
		if wordMatch[2] <= cp && cp <= wordMatch[5] { // within the range of whitespace+word
			if wordMatch[2] < cp && cp < wordMatch[3] { // within the range of whitespace only
				// fake match - this is so the correct completion is displayed in the following situation:
				// "set   dark-mode"
				// "    ^          "
				wordMatchesS = append(wordMatchesS[0:wordIdx], append([][]string{{"", "", ""}}, wordMatchesS[wordIdx:len(wordMatchesS)]...)...)
				wordStart = cp
				wordEnd = cp
			}
			break
		}
	}

	toks := make([]string, 0)
	for _, s := range wordMatchesS {
		toks = append(toks, s[2])
	}

	if wordIdx > 0 {
		argIdx := wordIdx - 1                              // first argument to command
		if word, ok := w.actions[wordMatchesS[0][2]]; ok { //
			wordArgs := word.Arguments(toks[1:])
			if argIdx < len(wordArgs) {
				if !checkOffer || wordArgs[argIdx].OfferCompletion() {
					for _, complV := range wordArgs[argIdx].Completions() {
						// to bind properly
						compl := complV
						qcompl := compl
						if strings.Contains(qcompl, " ") {
							qcompl = "\"" + qcompl + "\""
						}
						partials = append(partials, partial{
							word: compl,
							line: txt[0:wordStart] + qcompl + txt[wordEnd:len(txt)], // what to use for line if user completes this
							cp:   wordStart + len(qcompl),
						})
					}
				}
			}
		}
	} else {
		// This is the first word matching
		keys := make([]string, 0, len(w.actions))
		for k, _ := range w.actions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, keyV := range keys {
			key := keyV
			act := w.actions[key]
			if (!checkOffer || act.OfferCompletion()) && strings.HasPrefix(key, txt) {
				partials = append(partials, partial{
					word: key,
					line: key,
					cp:   len(key),
				})
			}
		}
	}

	return partials
}

func (w *Widget) updateCompletions(app gowid.IApp) {
	txt := w.ed.Text()
	complWidgets := make([]gowid.IWidget, 0)
	partials := make([]partial, 0)
	if txt != "" || w.showAll {
		partials = w.getPartialsCompletions(true, app)
	}
	w.showAll = false

	for _, partialV := range partials {
		partial := partialV // avoid gotcha
		compBtn := button.NewBare(text.New(partial.word))
		compBtn.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, widget gowid.IWidget) {
			w.ed.SetText(partial.line, app)
			w.ed.SetCursorPos(partial.cp, app)
			w.pl.SetFocus(app, 1)
		}))

		complWidgets = append(complWidgets,
			isselected.New(
				compBtn,
				styled.New(compBtn, gowid.MakePaletteRef("minibuffer-buttons")),
				styled.New(compBtn, gowid.MakePaletteRef("minibuffer-buttons")),
			),
		)

	}

	walker := list.NewSimpleListWalker(complWidgets)
	if len(complWidgets) > 0 {
		walker.SetFocus(walker.Last(), app)
		selections := list.New(walker)
		sl2 := keepselected.New(selections)
		w.compl.SetSubWidget(sl2, app)
		w.selections = selections
	} else {
		// don't want anything to take focus if there are no completions
		w.compl.SetSubWidget(nullw, app)
		w.selections = nil
	}
}

func Open(w dialog.IOpenExt, container gowid.ISettableComposite, width gowid.IWidgetDimension, height gowid.IWidgetDimension, app gowid.IApp) {
	ov := overlay.New(w, container.SubWidget(),
		gowid.VAlignBottom{}, height, // Intended to mean use as much vertical space as you need
		gowid.HAlignLeft{Margin: 5, MarginRight: 5}, width)

	if _, ok := width.(gowid.IRenderFixed); ok {
		w.SetContentWidth(gowid.RenderFixed{}, app) // fixed or weight:1, ratio:0.5
	} else {
		w.SetContentWidth(gowid.RenderWithWeight{W: 1}, app) // fixed or weight:1, ratio:0.5
	}
	w.SetSavedSubWidget(container.SubWidget(), app)
	w.SetSavedContainer(container, app)
	container.SetSubWidget(ov, app)
	w.SetOpen(true, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
