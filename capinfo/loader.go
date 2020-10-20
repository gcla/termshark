// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package capinfo

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
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
	Capinfo(pcap string) pcap.IPcapCommand
}

type commands struct{}

func MakeCommands() commands {
	return commands{}
}

var _ ILoaderCmds = commands{}

func (c commands) Capinfo(pcapfile string) pcap.IPcapCommand {
	args := []string{pcapfile}
	return &pcap.Command{
		Cmd: exec.Command(termshark.CapinfosBin(), args...),
	}
}

//======================================================================

type Loader struct {
	cmds ILoaderCmds

	SuppressErrors bool // if true, don't report process errors e.g. at shutdown

	mainCtx      context.Context // cancelling this cancels the dependent contexts
	mainCancelFn context.CancelFunc

	capinfoCtx      context.Context
	capinfoCancelFn context.CancelFunc

	capinfoCmd pcap.IPcapCommand
}

func NewLoader(cmds ILoaderCmds, ctx context.Context) *Loader {
	res := &Loader{
		cmds: cmds,
	}
	res.mainCtx, res.mainCancelFn = context.WithCancel(ctx)
	return res
}

func (c *Loader) StopLoad() {
	if c.capinfoCancelFn != nil {
		c.capinfoCancelFn()
	}
}

//======================================================================

type ICapinfoCallbacks interface {
	OnCapinfoData(data string, closeMe chan struct{})
	AfterCapinfoEnd(success bool, closeMe chan<- struct{})
}

func (c *Loader) StartLoad(pcap string, app gowid.IApp, cb ICapinfoCallbacks) {
	termshark.TrackedGo(func() {
		c.loadCapinfoAsync(pcap, app, cb)
	}, Goroutinewg)
}

func (c *Loader) loadCapinfoAsync(pcapf string, app gowid.IApp, cb ICapinfoCallbacks) {
	c.capinfoCtx, c.capinfoCancelFn = context.WithCancel(c.mainCtx)

	c.capinfoCmd = c.cmds.Capinfo(pcapf)

	capinfoOut, err := c.capinfoCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(err, cb)
		return
	}

	defer func() {
		ch := make(chan struct{})
		cb.AfterCapinfoEnd(true, ch)
		<-ch
	}()

	pcap.HandleBegin(cb)
	defer func() {
		pcap.HandleEnd(cb)
	}()

	err = c.capinfoCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting capinfo %v: %v", c.capinfoCmd, err)
		pcap.HandleError(err, cb)
		return
	}

	log.Infof("Started capinfo command %v with pid %d", c.capinfoCmd, c.capinfoCmd.Pid())

	procWaitChan := make(chan error, 1)

	defer func() {
		procWaitChan <- c.capinfoCmd.Wait()
	}()

	termshark.TrackedGo(func() {
		var err error
		cancelled := c.capinfoCtx.Done()
	loop:
		for {
			select {
			case <-cancelled:
				err := termshark.KillIfPossible(c.capinfoCmd)
				if err != nil {
					log.Infof("Did not kill capinfo process: %v", err)
				}
				cancelled = nil
			case err = <-procWaitChan:
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
							"command": c.capinfoCmd.String(),
							"error":   err,
						})
						pcap.HandleError(cerr, cb)
					}
				}
				break loop
			}
		}
		c.capinfoCtx = nil
		c.capinfoCancelFn = nil
	}, Goroutinewg)

	buf := new(bytes.Buffer)
	buf.ReadFrom(capinfoOut)

	ch := make(chan struct{})
	cb.OnCapinfoData(buf.String(), ch)
	<-ch
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
