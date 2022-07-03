// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gdamore/tcell/v2"
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
	ov         *overlay.Widget
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
	Arguments([]string, gowid.IApp) []IArg
	OfferCompletion() bool
}

// IArg represents an argument to a minibuffer command e.g. "dark-mode" in the
// command "set dark-mode on".
type IArg interface {
	OfferCompletion() bool
	Completions() []string
}

type partial struct {
	word   string
	qword  string
	before string
	after  string
}

func (p *partial) Line() string {
	return p.before + p.qword + p.after
}

func (p *partial) CursorPos() int {
	return len(p.before + p.qword)
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
				D:       gowid.RenderWithWeight{W: 1},
			},
			&gowid.ContainerWidget{
				IWidget: bottom,
				D:       gowid.RenderWithUnits{U: 1},
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
				BackgroundStyle: gowid.MakePaletteRef("cmdline"),
				ButtonStyle:     gowid.MakePaletteRef("cmdline-button"),
				BorderStyle:     gowid.MakePaletteRef("cmdline-border"),
				Modal:           true,
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
				w.ed.SetText(partials[selectedIdx].Line(), app)
				w.ed.SetCursorPos(partials[selectedIdx].CursorPos(), app)
			}
			//default:
		}

	case len(words) == 1: // command itself may be partially provided. If there is only
		// one way for the command to be completed, allow it to be run.
		// User types "cl", partials would be ["clear-packets", "clear-filter"]
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
				if len(act.Arguments([]string{}, app)) == 0 {
					err := w.actions[partials[selectedIdx].word].Run(app, partials[selectedIdx].word)
					if err == nil {
						if w.IsOpen() {
							w.Close(app)
						}
					}
				}
			} else {
				if keyIsEnter {
					w.ed.SetText(partials[selectedIdx].Line(), app)
					w.ed.SetCursorPos(partials[selectedIdx].CursorPos(), app)
				} else {
					// This is tab - complete to the longest common prefix
					extraPrefix := ""
				loop:
					for j := len(words[len(words)-1]); true; j += 1 {
						var c rune
						for _, partial := range partials {
							if len(partial.word) <= j {
								break loop
							}
							if c == 0 {
								c = rune(partial.word[j])
							} else {
								if c != rune(partial.word[j]) {
									break loop
								}
							}
						}
						extraPrefix += string(c)
					}
					longestPrefixPartial := partials[selectedIdx]
					// if the user types e.g. "help " then hits tab, extraPrefix will be "" (no characters typed
					// to start selection of next argument) so don't complete.
					if extraPrefix != "" {
						// e.g. "cl" + "ear-" from ["clear-packets", "clear-filter"]
						longestPrefixPartial.qword = words[len(words)-1] + extraPrefix
						w.ed.SetText(longestPrefixPartial.Line(), app)
						w.ed.SetCursorPos(longestPrefixPartial.CursorPos(), app)
					}
				}
			}
		}

	default:
		if w.selections == nil {
			w.showAll = true
			w.updateCompletions(app)
		} else if keyIsEnter {
			// if the selections are being displayed and enter is hit, complete that selection
			partials := w.getPartialsCompletions(true, app)
			w.ed.SetText(partials[selectedIdx].Line(), app)
			w.ed.SetCursorPos(partials[selectedIdx].CursorPos(), app)
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
			wordArgs := word.Arguments(toks[1:], app)
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
							word:   compl,
							qword:  qcompl,
							before: txt[0:wordStart],
							after:  txt[wordEnd:len(txt)],
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
					word:   key,
					qword:  key,
					before: "",
					after:  "",
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
			w.ed.SetText(partial.Line(), app)
			w.ed.SetCursorPos(partial.CursorPos(), app)
			w.pl.SetFocus(app, 1)
		}))

		complWidgets = append(complWidgets,
			isselected.New(
				compBtn,
				styled.New(compBtn, gowid.MakePaletteRef("cmdline-button")),
				styled.New(compBtn, gowid.MakePaletteRef("cmdline-button")),
			),
		)

	}

	w.ov.SetHeight(gowid.RenderWithUnits{U: 3 + len(complWidgets)}, app)

	walker := list.NewSimpleListWalker(complWidgets)
	if len(complWidgets) > 0 {
		walker.SetFocus(walker.Last(), app)
		selections := list.New(walker)
		selections.GoToBottom(app)
		sl2 := keepselected.New(selections)
		w.compl.SetSubWidget(sl2, app)
		w.selections = selections
	} else {
		// don't want anything to take focus if there are no completions
		w.compl.SetSubWidget(nullw, app)
		w.selections = nil
	}
}

// w is minibuffer
// container is main view
func Open(w *Widget, container gowid.ISettableComposite, width gowid.IWidgetDimension, app gowid.IApp) {
	w.ov = overlay.New(w, container.SubWidget(),
		gowid.VAlignBottom{}, gowid.RenderWithUnits{U: 3}, // Intended to mean use as much vertical space as you need
		gowid.HAlignLeft{Margin: 5, MarginRight: 5}, width,
		overlay.Options{
			IgnoreLowerStyle: true,
		},
	)

	if _, ok := width.(gowid.IRenderFixed); ok {
		w.SetContentWidth(gowid.RenderFixed{}, app) // fixed or weight:1, ratio:0.5
	} else {
		w.SetContentWidth(gowid.RenderWithWeight{W: 1}, app) // fixed or weight:1, ratio:0.5
	}
	w.SetSavedSubWidget(container.SubWidget(), app)
	w.SetSavedContainer(container, app)
	container.SetSubWidget(w.ov, app)
	w.SetOpen(true, app)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
