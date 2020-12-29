// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

//======================================================================

type IClear interface {
	OnClear()
}

type INewSource interface {
	OnNewSource()
}

type IOnError interface {
	OnError(err error)
}

type IBeforeBegin interface {
	BeforeBegin()
}

type IAfterEnd interface {
	AfterEnd()
}

type IUnpack interface {
	Unpack() []interface{}
}

type HandlerList []interface{}

func (h HandlerList) Unpack() []interface{} {
	return h
}

type unpackedHandlerFunc func(interface{}) bool

func HandleUnpack(cb interface{}, handler unpackedHandlerFunc) bool {
	if c, ok := cb.(IUnpack); ok {
		handlers := c.Unpack()
		for _, cb := range handlers {
			handler(cb) // will wait on channel if it has to, doesn't matter if not
		}
		return true
	}
	return false
}

func HandleBegin(cb interface{}) bool {
	res := false
	if !HandleUnpack(cb, HandleBegin) {
		if c, ok := cb.(IBeforeBegin); ok {
			c.BeforeBegin()
			res = true
		}
	}
	return res
}

func HandleEnd(cb interface{}) bool {
	res := false
	if !HandleUnpack(cb, HandleEnd) {
		if c, ok := cb.(IAfterEnd); ok {
			c.AfterEnd()
			res = true
		}
	}
	return res
}

func HandleError(err error, cb interface{}) bool {
	res := false
	if !HandleUnpack(cb, func(cb2 interface{}) bool {
		return HandleError(err, cb2)
	}) {
		if ec, ok := cb.(IOnError); ok {
			ec.OnError(err)
			res = true
		}
	}
	return res
}

func handleClear(cb interface{}) bool {
	res := false
	if !HandleUnpack(cb, handleClear) {
		if c, ok := cb.(IClear); ok {
			c.OnClear()
			res = true
		}
	}
	return res
}

func handleNewSource(cb interface{}) bool {
	res := false
	if !HandleUnpack(cb, handleNewSource) {
		if c, ok := cb.(INewSource); ok {
			c.OnNewSource()
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
