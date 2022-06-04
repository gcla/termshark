// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/xml"
	"io"

	"github.com/mreiferson/go-snappystream"
)

//======================================================================

type IPdmlPacket interface {
	Packet() PdmlPacket
}

type PdmlPacket struct {
	XMLName xml.Name `xml:"packet"`
	Content []byte   `xml:",innerxml"`
}

var _ IPdmlPacket = PdmlPacket{}

func (p PdmlPacket) Packet() PdmlPacket {
	return p
}

//======================================================================

type GzippedPdmlPacket struct {
	Data bytes.Buffer
}

var _ IPdmlPacket = GzippedPdmlPacket{}

func (p GzippedPdmlPacket) Packet() PdmlPacket {
	return p.Uncompress()
}

func (p GzippedPdmlPacket) Uncompress() PdmlPacket {
	greader, err := gzip.NewReader(&p.Data)
	if err != nil {
		panic(err)
	}
	decoder := gob.NewDecoder(greader)
	var res PdmlPacket
	err = decoder.Decode(&res)
	if err != nil {
		panic(err)
	}

	return res
}

func GzipPdmlPacket(p PdmlPacket) IPdmlPacket {
	res := GzippedPdmlPacket{}
	gwriter := gzip.NewWriter(&res.Data)
	encoder := gob.NewEncoder(gwriter)
	err := encoder.Encode(p)
	if err != nil {
		panic(err)
	}
	gwriter.Close()
	return res
}

//======================================================================

type SnappiedPdmlPacket struct {
	Data bytes.Buffer
}

var _ IPdmlPacket = SnappiedPdmlPacket{}

func (p SnappiedPdmlPacket) Packet() PdmlPacket {
	return p.Uncompress()
}

func (p SnappiedPdmlPacket) Uncompress() PdmlPacket {
	var res PdmlPacket
	UnsnappyMe(&res, &p.Data)
	return res
}

func SnappyPdmlPacket(p PdmlPacket) IPdmlPacket {
	res := SnappiedPdmlPacket{}
	SnappyMe(p, &res.Data)
	return res
}

//======================================================================

// SnappyMe compresses the object within interface p to the
// writer w.
func SnappyMe(p interface{}, w io.Writer) {
	gwriter := snappystream.NewBufferedWriter(w)
	encoder := gob.NewEncoder(gwriter)
	if err := encoder.Encode(p); err != nil {
		panic(err)
	}
	gwriter.Close()
}

// UnsnappyMe decompresses from reader r into res. Afterwards,
// res will be an interface whose type is a pointer to whatever
// was serialized in the first place.
func UnsnappyMe(res interface{}, r io.Reader) {
	greader := snappystream.NewReader(r, false)
	decoder := gob.NewDecoder(greader)
	if err := decoder.Decode(res); err != nil {
		panic(err)
	}
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
