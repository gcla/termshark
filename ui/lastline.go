// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package ui contains user-interface functions and helpers for termshark.
package ui

import (
	"fmt"
	"strconv"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/widgets/minibuffer"
	"github.com/gdamore/tcell/terminfo"
	"github.com/gdamore/tcell/terminfo/dynamic"
)

//======================================================================

var notEnoughArgumentsErr = fmt.Errorf("Not enough arguments provided")
var invalidSetCommandErr = fmt.Errorf("Invalid set command")

type minibufferFn func(gowid.IApp, ...string) error

func (m minibufferFn) Run(app gowid.IApp, args ...string) error {
	return m(app, args...)
}

func (m minibufferFn) OfferCompletion() bool {
	return true
}

func (m minibufferFn) Arguments([]string) []minibuffer.IArg {
	return nil
}

type quietMinibufferFn func(gowid.IApp, ...string) error

func (m quietMinibufferFn) Run(app gowid.IApp, args ...string) error {
	return m(app, args...)
}

func (m quietMinibufferFn) OfferCompletion() bool {
	return false
}

func (m quietMinibufferFn) Arguments([]string) []minibuffer.IArg {
	return nil
}

//======================================================================

type boolArg struct {
	arg string
}

var _ minibuffer.IArg = boolArg{}

func (s boolArg) OfferCompletion() bool {
	return true
}

// return these in sorted order
func (s boolArg) Completions() []string {
	return []string{"false", "true"}
}

//======================================================================

type onOffArg struct {
	arg string
}

var _ minibuffer.IArg = onOffArg{}

func (s onOffArg) OfferCompletion() bool {
	return true
}

// return these in sorted order
func (s onOffArg) Completions() []string {
	return []string{"off", "on"}
}

//======================================================================

type unhelpfulArg struct {
	arg string
}

var _ minibuffer.IArg = unhelpfulArg{}

func (s unhelpfulArg) OfferCompletion() bool {
	return false
}

// return these in sorted order
func (s unhelpfulArg) Completions() []string {
	return nil
}

//======================================================================

type setArg struct{}

var _ minibuffer.IArg = setArg{}

func (s setArg) OfferCompletion() bool {
	return true
}

// return these in sorted order
func (s setArg) Completions() []string {
	return []string{
		"auto-scroll",
		"copy-command-timeout",
		"dark-mode",
		"disable-shark-fin",
		"packet-colors",
		"pager",
		"nopager",
		"term",
		"noterm",
	}
}

//======================================================================

func stringIn(s string, a []string) bool {
	for _, s2 := range a {
		if s == s2 {
			return true
		}
	}
	return false
}

func parseOnOff(str string) (bool, error) {
	switch str {
	case "on", "ON", "On":
		return true, nil
	case "off", "OFF", "Off":
		return false, nil
	}
	return false, strconv.ErrSyntax
}

func validateTerm(term string) error {
	var err error
	_, err = terminfo.LookupTerminfo(term)
	if err != nil {
		_, _, err = dynamic.LoadTerminfo(term)
	}
	return err
}

type setCommand struct{}

var _ minibuffer.IAction = setCommand{}

func (d setCommand) Run(app gowid.IApp, args ...string) error {
	var err error
	var b bool
	var i uint64
	switch len(args) {
	case 3:
		switch args[1] {
		case "auto-scroll":
			if b, err = parseOnOff(args[2]); err == nil {
				AutoScroll = b
				termshark.SetConf("main.auto-scroll", AutoScroll)
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					OpenMessage(fmt.Sprintf("Packet auto-scroll is now %s", gwutil.If(b, "on", "off").(string)), appView, app)
				}))
			}
		case "copy-command-timeout":
			if i, err = strconv.ParseUint(args[2], 10, 32); err == nil {
				termshark.SetConf("main.copy-command-timeout", i)
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					OpenMessage(fmt.Sprintf("Copy command timeout is now %ds", i), appView, app)
				}))
			}
		case "dark-mode":
			if b, err = parseOnOff(args[2]); err == nil {
				DarkMode = b
				termshark.SetConf("main.dark-mode", DarkMode)
			}
		case "disable-shark-fin":
			if b, err = strconv.ParseBool(args[2]); err == nil {
				termshark.SetConf("main.disable-shark-fin", DarkMode)
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					OpenMessage(fmt.Sprintf("Shark-saver is now %s", gwutil.If(b, "off", "on").(string)), appView, app)
				}))
			}
		case "packet-colors":
			if b, err = parseOnOff(args[2]); err == nil {
				PacketColors = b
				termshark.SetConf("main.packet-colors", PacketColors)
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					OpenMessage(fmt.Sprintf("Packet colors are now %s", gwutil.If(b, "on", "off").(string)), appView, app)
				}))
			}
		case "term":
			if err = validateTerm(args[2]); err == nil {
				termshark.SetConf("main.term", args[2])
				app.Run(gowid.RunFunction(func(app gowid.IApp) {
					OpenMessage(fmt.Sprintf("Terminal type is now %s\n(Requires restart)", args[2]), appView, app)
				}))
			}
		case "pager":
			termshark.SetConf("main.pager", args[2])
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				OpenMessage(fmt.Sprintf("Pager is now %s", args[2]), appView, app)
			}))
		default:
			err = invalidSetCommandErr
		}
	case 2:
		switch args[1] {
		case "noterm":
			termshark.DeleteConf("main.term")
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				OpenMessage("Terminal type is now unset\n(Requires restart)", appView, app)
			}))
		case "nopager":
			termshark.DeleteConf("main.pager")
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				OpenMessage("Pager is now unset", appView, app)
			}))
		default:
			err = invalidSetCommandErr
		}
	}

	if err != nil {
		OpenMessage(fmt.Sprintf("Error: %s", err), appView, app)
	}

	return err
}

func (d setCommand) OfferCompletion() bool {
	return true
}

func (d setCommand) Arguments(toks []string) []minibuffer.IArg {
	res := make([]minibuffer.IArg, 0)
	res = append(res, setArg{})

	if len(toks) > 0 {
		onOffCmds := []string{"auto-scroll", "dark-mode", "packet-colors"}
		boolCmds := []string{"disable-shark-fin"}
		intCmds := []string{"disk-cache-size-mb", "copy-command-timeout"}

		if stringIn(toks[0], boolCmds) {
			res = append(res, boolArg{})
		} else if stringIn(toks[0], intCmds) {
			res = append(res, unhelpfulArg{})
		} else if stringIn(toks[0], onOffCmds) {
			res = append(res, onOffArg{})
		}
	}

	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
