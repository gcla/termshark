// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package streams

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"

	"github.com/gcla/gowid"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pcap"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var Goroutinewg *sync.WaitGroup

//======================================================================

type ILoaderCmds interface {
	Stream(pcap string, proto string, idx int) pcap.IPcapCommand
	Indexer(pcap string, proto string, idx int) pcap.IPcapCommand
}

type commands struct{}

func MakeCommands() commands {
	return commands{}
}

var _ ILoaderCmds = commands{}

func (c commands) Stream(pcapfile string, proto string, idx int) pcap.IPcapCommand {
	args := []string{"-r", pcapfile, "-q", "-z", fmt.Sprintf("follow,%s,raw,%d", proto, idx)}
	return &pcap.Command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

// startAt is zero-indexed
func (c commands) Indexer(pcapfile string, proto string, idx int) pcap.IPcapCommand {
	args := []string{"-T", "pdml", "-r", pcapfile, "-Y", fmt.Sprintf("%s.stream eq %d", proto, idx)}
	return &pcap.Command{Cmd: exec.Command(termshark.TSharkBin(), args...)}
}

//======================================================================

type Loader struct {
	cmds ILoaderCmds

	SuppressErrors bool // if true, don't report process errors e.g. at shutdown

	mainCtx      context.Context // cancelling this cancels the dependent contexts
	mainCancelFn context.CancelFunc

	streamCtx      context.Context // cancels the iface reader process
	streamCancelFn context.CancelFunc

	indexerCtx      context.Context // cancels the stream indexer process
	indexerCancelFn context.CancelFunc

	streamCmd  pcap.IPcapCommand
	indexerCmd pcap.IPcapCommand
}

func NewLoader(cmds ILoaderCmds, ctx context.Context) *Loader {
	res := &Loader{
		cmds: cmds,
	}
	res.mainCtx, res.mainCancelFn = context.WithCancel(ctx)
	return res
}

func (c *Loader) stopLoad() {
	if c.streamCancelFn != nil {
		c.streamCancelFn()
	}
}

//======================================================================

type ITrackPayload interface {
	TrackPayloadPacket(packet int)
}

type IIndexerCallbacks interface {
	IOnStreamChunk
	ITrackPayload
	AfterIndexEnd(success bool, closeMe chan<- struct{})
}

func (c *Loader) StartLoad(pcap string, proto string, idx int, app gowid.IApp, cb IIndexerCallbacks) {
	termshark.TrackedGo(func() {
		c.loadStreamReassemblyAsync(pcap, proto, idx, app, cb)
	}, Goroutinewg)

	termshark.TrackedGo(func() {
		c.startStreamIndexerAsync(pcap, proto, idx, app, cb)
	}, Goroutinewg)
}

type ISavedData interface {
	NumChunks() int
	Chunk(i int) IChunk
}

func (c *Loader) loadStreamReassemblyAsync(pcapf string, proto string, idx int, app gowid.IApp, cb interface{}) {
	c.streamCtx, c.streamCancelFn = context.WithCancel(c.mainCtx)

	defer func() {
		c.streamCtx = nil
		c.streamCancelFn = nil
	}()

	c.streamCmd = c.cmds.Stream(pcapf, proto, idx)

	streamOut, err := c.streamCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(err, cb)
		return
	}

	pcap.HandleBegin(cb)
	defer func() {
		pcap.HandleEnd(cb)
	}()

	err = c.streamCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting stream reassembly %v: %v", c.streamCmd, err)
		pcap.HandleError(err, cb)
		return
	}

	log.Infof("Started stream reassembly command %v with pid %d", c.streamCmd, c.streamCmd.Pid())

	defer func() {
		err = c.streamCmd.Wait() // it definitely started, so we must wait
		if !c.SuppressErrors && err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
					"command": c.streamCmd.String(),
					"error":   err,
				})
				pcap.HandleError(cerr, cb)
			}
		}
	}()

	termshark.TrackedGo(func() {
		// Wait for external cancellation. This is the shutdown procedure.
		<-c.streamCtx.Done()
		err := termshark.KillIfPossible(c.streamCmd)
		if err != nil {
			log.Infof("Did not kill stream reassembly process: %v", err)
		}
	}, Goroutinewg)

	var ops []Option
	ops = append(ops, GlobalStore("app", app))
	ops = append(ops, GlobalStore("context", c.streamCtx))
	ops = append(ops, GlobalStore("callbacks", cb))
	func() {
		_, err := ParseReader("", streamOut, ops...)
		if err != nil {
			log.Infof("Stream parser reported error: %v", err)
		}
	}()

	c.streamCancelFn()
}

func (c *Loader) startStreamIndexerAsync(pcapf string, proto string, idx int, app gowid.IApp, cb IIndexerCallbacks) {
	res := false

	c.indexerCtx, c.indexerCancelFn = context.WithCancel(c.mainCtx)

	defer func() {
		c.indexerCtx = nil
		c.indexerCancelFn = nil
	}()

	c.indexerCmd = c.cmds.Indexer(pcapf, proto, idx)

	streamOut, err := c.indexerCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(err, cb)
		return
	}

	defer func() {
		ch := make(chan struct{})
		cb.AfterIndexEnd(res, ch)
		<-ch
	}()

	err = c.indexerCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting stream indexer %v: %v", c.indexerCmd, err)
		pcap.HandleError(err, cb)
		return
	}

	log.Infof("Started stream indexer command %v with pid %d", c.indexerCmd, c.indexerCmd.Pid())

	defer func() {
		err = c.indexerCmd.Wait() // it definitely started, so we must wait
		if !c.SuppressErrors && err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
					"command": c.indexerCmd.String(),
					"error":   err,
				})
				pcap.HandleError(cerr, cb)
			}
		}
	}()

	termshark.TrackedGo(func() {
		// Wait for external cancellation. This is the shutdown procedure.
		<-c.indexerCtx.Done()
		err := termshark.KillIfPossible(c.indexerCmd)
		if err != nil {
			log.Infof("Did not kill indexer process: %v", err)
		}
		// Stop main loop
		streamOut.Close()
	}, Goroutinewg)

	decodeStreamXml(streamOut, proto, c.indexerCtx, cb)

	res = true

	c.indexerCancelFn()
}

func decodeStreamXml(streamOut io.Reader, proto string, ctx context.Context, cb ITrackPayload) {
	inTCP := false
	inUDP := false
	curPkt := 0
	curDataLen := 0

	d := xml.NewDecoder(streamOut)
	for {
		if ctx.Err() != nil {
			break
		}
		t, tokenErr := d.Token()
		if tokenErr != nil {
			if tokenErr == io.EOF {
				break
			}
		}
		switch t := t.(type) {
		case xml.EndElement:
			switch t.Name.Local {
			case "packet":
				if curDataLen > 0 {
					cb.TrackPayloadPacket(curPkt)
				}
				curPkt++
				curDataLen = 0
				inTCP = false
				inUDP = false
			}

		case xml.StartElement:
			switch t.Name.Local {
			case "proto":
				for _, attr := range t.Attr {
					if attr.Name.Local == "name" {
						switch attr.Value {
						case "tcp":
							inTCP = true
						case "udp":
							inUDP = true
						}
						break
					}
				}
			case "field":
			aloop:
				for _, attr := range t.Attr {
					if attr.Name.Local == "name" {
						switch attr.Value {
						case "tcp.len":
							if proto == "tcp" && inTCP {
								for _, attr2 := range t.Attr {
									if attr2.Name.Local == "show" {
										if val, err := strconv.Atoi(attr2.Value); err == nil {
											// add val to end of list for tcp:curTCP
											curDataLen = val
										}
										break aloop
									}
								}
							}
						case "udp.length":
							if proto == "udp" && inUDP {
								for _, attr2 := range t.Attr {
									if attr2.Name.Local == "show" {
										if val, err := strconv.Atoi(attr2.Value); err == nil {
											// add val to end of list for udp:curUDP
											curDataLen = val
										}
										break aloop
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

//======================================================================

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
