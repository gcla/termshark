// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package pcap

import (
	"fmt"
	"os"
	"strings"

	"github.com/gcla/termshark/v2/pkg/system"
)

//======================================================================

type IPacketSource interface {
	Name() string
	IsFile() bool
	IsInterface() bool
	IsFifo() bool
	IsPipe() bool
}

//======================================================================

func FileSystemSources(srcs []IPacketSource) []IPacketSource {
	res := make([]IPacketSource, 0)
	for _, src := range srcs {
		if src.IsFile() {
			res = append(res, src)
		}
	}
	return res
}

func SourcesString(srcs []IPacketSource) string {
	return strings.Join(SourcesNames(srcs), " + ")
}

func SourcesNames(srcs []IPacketSource) []string {
	names := make([]string, 0, len(srcs))
	for _, psrc := range srcs {
		names = append(names, psrc.Name())
	}
	return names
}

func UIName(src IPacketSource) string {
	if src.IsPipe() {
		return "<stdin>"
	} else {
		return src.Name()
	}
}

func CanRestart(src IPacketSource) bool {
	return src.IsFile() || src.IsInterface()
}

//======================================================================

type FileSource struct {
	Filename string
}

var _ IPacketSource = FileSource{}

func (p FileSource) Name() string {
	return p.Filename
}

func (p FileSource) IsFile() bool {
	return true
}

func (p FileSource) IsInterface() bool {
	return false
}

func (p FileSource) IsFifo() bool {
	return false
}

func (p FileSource) IsPipe() bool {
	return false
}

func (p FileSource) String() string {
	return fmt.Sprintf("File:%s", p.Filename)
}

//======================================================================

type TemporaryFileSource struct {
	FileSource
}

type ISourceRemover interface {
	Remove() error
}

func (p TemporaryFileSource) Remove() error {
	return os.Remove(p.Filename)
}

func (p TemporaryFileSource) String() string {
	return fmt.Sprintf("TempFile:%s", p.Filename)
}

//======================================================================

type InterfaceSource struct {
	Iface string
}

var _ IPacketSource = InterfaceSource{}

func (p InterfaceSource) Name() string {
	return p.Iface
}

func (p InterfaceSource) IsFile() bool {
	return false
}

func (p InterfaceSource) IsInterface() bool {
	return true
}

func (p InterfaceSource) IsFifo() bool {
	return false
}

func (p InterfaceSource) IsPipe() bool {
	return false
}

func (p InterfaceSource) String() string {
	return fmt.Sprintf("Interface:%s", p.Iface)
}

//======================================================================

type FifoSource struct {
	Filename string
}

var _ IPacketSource = FifoSource{}

func (p FifoSource) Name() string {
	return p.Filename
}

func (p FifoSource) IsFile() bool {
	return false
}

func (p FifoSource) IsInterface() bool {
	return false
}

func (p FifoSource) IsFifo() bool {
	return true
}

func (p FifoSource) IsPipe() bool {
	return false
}

func (p FifoSource) String() string {
	return fmt.Sprintf("Fifo:%s", p.Filename)
}

//======================================================================

type PipeSource struct {
	Descriptor string
	Fd         int
}

var _ IPacketSource = PipeSource{}

func (p PipeSource) Name() string {
	return p.Descriptor
}

func (p PipeSource) IsFile() bool {
	return false
}

func (p PipeSource) IsInterface() bool {
	return false
}

func (p PipeSource) IsFifo() bool {
	return false
}

func (p PipeSource) IsPipe() bool {
	return true
}

func (p PipeSource) Close() error {
	system.CloseDescriptor(p.Fd)
	return nil
}

func (p PipeSource) String() string {
	return fmt.Sprintf("Pipe:%s(%d)", p.Descriptor, p.Fd)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
