// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import "github.com/gcla/gowid"

//======================================================================

type HandlerCode int

const (
	NoneCode HandlerCode = 1 << iota
	PdmlCode
	PsmlCode
	TailCode
	IfaceCode
	ConvCode
	StreamCode
	CapinfoCode
)

type IClear interface {
	OnClear(code HandlerCode, app gowid.IApp)
}

type INewSource interface {
	OnNewSource(code HandlerCode, app gowid.IApp)
}

type IOnError interface {
	OnError(code HandlerCode, app gowid.IApp, err error)
}

type IBeforeBegin interface {
	BeforeBegin(code HandlerCode, app gowid.IApp)
}

type IAfterEnd interface {
	AfterEnd(code HandlerCode, app gowid.IApp)
}

type IPsmlHeader interface {
	OnPsmlHeader(code HandlerCode, app gowid.IApp)
}

type IUnpack interface {
	Unpack() []interface{}
}

type HandlerList []interface{}

func (h HandlerList) Unpack() []interface{} {
	return h
}

type unpackedHandlerFunc func(HandlerCode, gowid.IApp, interface{}) bool

func HandleUnpack(code HandlerCode, cb interface{}, handler unpackedHandlerFunc, app gowid.IApp) bool {
	if c, ok := cb.(IUnpack); ok {
		handlers := c.Unpack()
		for _, cb := range handlers {
			handler(code, app, cb) // will wait on channel if it has to, doesn't matter if not
		}
		return true
	}
	return false
}

func HandleBegin(code HandlerCode, app gowid.IApp, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, HandleBegin, app) {
		if c, ok := cb.(IBeforeBegin); ok {
			c.BeforeBegin(code, app)
			res = true
		}
	}
	return res
}

func HandleEnd(code HandlerCode, app gowid.IApp, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, HandleEnd, app) {
		if c, ok := cb.(IAfterEnd); ok {
			c.AfterEnd(code, app)
			res = true
		}
	}
	return res
}

func HandleError(code HandlerCode, app gowid.IApp, err error, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, func(code HandlerCode, app gowid.IApp, cb2 interface{}) bool {
		return HandleError(code, app, err, cb2)
	}, app) {
		if ec, ok := cb.(IOnError); ok {
			ec.OnError(code, app, err)
			res = true
		}
	}
	return res
}

func handlePsmlHeader(code HandlerCode, app gowid.IApp, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, handlePsmlHeader, app) {
		if c, ok := cb.(IPsmlHeader); ok {
			c.OnPsmlHeader(code, app)
			res = true
		}
	}
	return res
}

func handleClear(code HandlerCode, app gowid.IApp, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, handleClear, app) {
		if c, ok := cb.(IClear); ok {
			c.OnClear(code, app)
			res = true
		}
	}
	return res
}

func handleNewSource(code HandlerCode, app gowid.IApp, cb interface{}) bool {
	res := false
	if !HandleUnpack(code, cb, handleNewSource, app) {
		if c, ok := cb.(INewSource); ok {
			c.OnNewSource(code, app)
			res = true
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
