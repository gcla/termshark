// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/termshark/v2/pkg/pcap"
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

	streamCtx      context.Context // cancels the stream chunk reader process
	streamCancelFn context.CancelFunc

	indexerCtx      context.Context // cancels the stream indexer (pdml) process
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

// Called by user to cancel a stream reassembly op. Stops both processes straight away.
// Note that typically, the indexer will be further behind.
func (c *Loader) StopLoad() {
	c.SuppressErrors = true
	if c.streamCancelFn != nil {
		c.streamCancelFn()
	}
	if c.indexerCancelFn != nil {
		c.indexerCancelFn()
	}
}

//======================================================================

type ITrackPayload interface {
	TrackPayloadPacket(packet int)
}

type IIndexerCallbacks interface {
	IOnStreamChunk
	ITrackPayload
	AfterIndexEnd(success bool)
}

func (c *Loader) StartLoad(pcap string, proto string, idx int, app gowid.IApp, cb IIndexerCallbacks) {
	c.SuppressErrors = false

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

	procChan := make(chan int)
	pid := 0

	defer func() {
		if pid == 0 {
			close(procChan)
		}
	}()

	c.streamCmd = c.cmds.Stream(pcapf, proto, idx)

	termChan := make(chan error)

	termshark.TrackedGo(func() {
		var err error
		origCmd := c.streamCmd
		cancelled := c.streamCtx.Done()
		procChan := procChan
		state := pcap.NotStarted

		kill := func() {
			err := termshark.KillIfPossible(origCmd)
			if err != nil {
				log.Infof("Did not kill tshark stream process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-termChan:
				state = pcap.Terminated
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						pcap.HandleError(pcap.StreamCode, app, pcap.MakeUsefulError(c.streamCmd, err), cb)
					}
				}

			case pid := <-procChan:
				procChan = nil
				if pid != 0 {
					state = pcap.Started
					if cancelled == nil {
						kill()
					}
				}

			case <-cancelled:
				cancelled = nil
				if state == pcap.Started {
					kill()
				}
			}

			if state == pcap.Terminated || (procChan == nil && state == pcap.NotStarted) {
				break loop
			}
		}
	}, Goroutinewg)

	streamOut, err := c.streamCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(pcap.StreamCode, app, err, cb)
		return
	}

	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		pcap.HandleBegin(pcap.StreamCode, app, cb)
	}))
	defer func() {
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			pcap.HandleEnd(pcap.StreamCode, app, cb)
		}))
	}()

	err = c.streamCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting stream reassembly %v: %v", c.streamCmd, err)
		pcap.HandleError(pcap.StreamCode, app, err, cb)
		return
	}

	log.Infof("Started stream reassembly command %v with pid %d", c.streamCmd, c.streamCmd.Pid())

	defer func() {
		termChan <- c.streamCmd.Wait()
	}()

	pid = c.streamCmd.Pid()
	procChan <- pid

	var ops []Option
	ops = append(ops, GlobalStore("app", app))
	ops = append(ops, GlobalStore("context", c.streamCtx))
	ops = append(ops, GlobalStore("callbacks", cb))
	func() {
		_, err := ParseReader("", streamOut, ops...)
		if err != nil {
			log.Warnf("Stream parser reported error: %v", err)
		}
	}()

	c.streamCancelFn()
}

func (c *Loader) startStreamIndexerAsync(pcapf string, proto string, idx int, app gowid.IApp, cb IIndexerCallbacks) {
	res := false

	procChan := make(chan int)
	pid := 0

	defer func() {
		if pid == 0 {
			close(procChan)
		}
	}()

	c.indexerCtx, c.indexerCancelFn = context.WithCancel(c.mainCtx)

	c.indexerCmd = c.cmds.Indexer(pcapf, proto, idx)

	streamOut, err := c.indexerCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(pcap.StreamCode, app, err, cb)
		return
	}

	procWaitChan := make(chan error, 1)

	termshark.TrackedGo(func() {
		var err error
		cancelledChan := c.indexerCtx.Done()
		procChan := procChan
		state := pcap.NotStarted

		kill := func() {
			err = termshark.KillIfPossible(c.indexerCmd)
			if err != nil {
				log.Infof("Did not kill indexer process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-procWaitChan:
				state = pcap.Terminated
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						pcap.HandleError(pcap.StreamCode, app, pcap.MakeUsefulError(c.indexerCmd, err), cb)
					}
				}
				streamOut.Close()

			case pid := <-procChan:
				procChan = nil
				if pid != 0 {
					state = pcap.Started
					if cancelledChan == nil {
						kill()
					}
				}

			case <-cancelledChan:
				cancelledChan = nil
				if state == pcap.Started {
					kill()
				}

			}

			if state == pcap.Terminated || (procChan == nil && state == pcap.NotStarted) {
				break loop
			}

		}
	}, Goroutinewg)

	defer func() {
		cb.AfterIndexEnd(res)
	}()

	err = c.indexerCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting stream indexer %v: %v", c.indexerCmd, err)
		pcap.HandleError(pcap.StreamCode, app, err, cb)
		return
	}

	log.Infof("Started stream indexer command %v with pid %d", c.indexerCmd, c.indexerCmd.Pid())

	defer func() {
		procWaitChan <- c.indexerCmd.Wait()
	}()

	pid = c.indexerCmd.Pid()
	procChan <- pid

	res = decodeStreamXml(streamOut, proto, c.indexerCtx, cb)
}

func decodeStreamXml(streamOut io.Reader, proto string, ctx context.Context, cb ITrackPayload) bool {
	inTCP := false
	inUDP := false
	curPkt := 0
	curDataLen := 0
	res := false

	d := xml.NewDecoder(streamOut)
	for {
		if ctx.Err() != nil {
			break
		}
		t, tokenErr := d.Token()
		if tokenErr != nil {
			if tokenErr == io.EOF {
				res = true
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

	return res
}

//======================================================================

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
