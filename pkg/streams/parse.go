// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"encoding/hex"
	"fmt"
	"strings"
)

//======================================================================

type IChunk interface {
	Direction() Direction
	StreamData() []byte
}

type IOnStreamChunk interface {
	OnStreamChunk(chunk IChunk)
}

type IOnStreamHeader interface {
	OnStreamHeader(header FollowHeader)
}

//======================================================================

type parseContext interface {
	Err() error
}

type StreamParseError struct{}

func (e StreamParseError) Error() string {
	return "Stream reassembly parse error"
}

var _ error = StreamParseError{}

//======================================================================

type Protocol int

const (
	Unspecified Protocol = 0
	TCP         Protocol = iota
	UDP         Protocol = iota
)

var _ fmt.Stringer = Protocol(0)

func (p Protocol) String() string {
	switch p {
	case Unspecified:
		return "Unspecified"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		panic(nil)
	}
}

//======================================================================

type Direction int

const (
	Client Direction = 0
	Server Direction = iota
)

func (d Direction) String() string {
	switch d {
	case Client:
		return "Client"
	case Server:
		return "Server"
	default:
		return "Unknown!"
	}
}

//======================================================================

type Bytes struct {
	Dirn Direction
	Data []byte
}

var _ fmt.Stringer = Bytes{}
var _ IChunk = Bytes{}

func (b Bytes) Direction() Direction {
	return b.Dirn
}

func (b Bytes) StreamData() []byte {
	return b.Data
}

func (b Bytes) String() string {
	return fmt.Sprintf("Direction: %v\n%s", b.Dirn, hex.Dump(b.Data))
}

//======================================================================

type FollowHeader struct {
	Follow string
	Filter string
	Node0  string
	Node1  string
}

func (h FollowHeader) String() string {
	return fmt.Sprintf("[client:%s server:%s follow:%s filter:%s]", h.Node0, h.Node1, h.Follow, h.Filter)
}

type FollowStream struct {
	FollowHeader
	Bytes []Bytes
}

var _ fmt.Stringer = FollowStream{}

func (f FollowStream) String() string {
	datastrs := make([]string, 0, len(f.Bytes))
	for _, b := range f.Bytes {
		datastrs = append(datastrs, b.String())
	}
	data := strings.Join(datastrs, "\n")
	return fmt.Sprintf("Follow: %s\nFilter: %s\nNode0: %s\nNode1: %s\nData:\n%s", f.Follow, f.Filter, f.Node0, f.Node1, data)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
