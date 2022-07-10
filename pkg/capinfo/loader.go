// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/termshark/v2/pkg/pcap"
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
	OnCapinfoData(data string)
	AfterCapinfoEnd(success bool)
}

func (c *Loader) StartLoad(pcap string, app gowid.IApp, cb ICapinfoCallbacks) {
	termshark.TrackedGo(func() {
		c.loadCapinfoAsync(pcap, app, cb)
	}, Goroutinewg)
}

func (c *Loader) loadCapinfoAsync(pcapf string, app gowid.IApp, cb ICapinfoCallbacks) {
	c.capinfoCtx, c.capinfoCancelFn = context.WithCancel(c.mainCtx)

	procChan := make(chan int)
	pid := 0

	defer func() {
		if pid == 0 {
			close(procChan)
		}
	}()

	c.capinfoCmd = c.cmds.Capinfo(pcapf)

	termChan := make(chan error)

	termshark.TrackedGo(func() {
		var err error
		cmd := c.capinfoCmd
		cancelledChan := c.capinfoCtx.Done()
		procChan := procChan
		state := pcap.NotStarted

		kill := func() {
			err := termshark.KillIfPossible(cmd)
			if err != nil {
				log.Infof("Did not kill tshark capinfos process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-termChan:
				state = pcap.Terminated
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						pcap.HandleError(pcap.CapinfoCode, app, pcap.MakeUsefulError(c.capinfoCmd, err), cb)
					}
				}

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

	capinfoOut, err := c.capinfoCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(pcap.CapinfoCode, app, err, cb)
		return
	}

	defer func() {
		cb.AfterCapinfoEnd(true)
	}()

	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		pcap.HandleBegin(pcap.CapinfoCode, app, cb)
	}))
	defer func() {
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			pcap.HandleEnd(pcap.CapinfoCode, app, cb)
		}))
	}()

	err = c.capinfoCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting capinfo %v: %v", c.capinfoCmd, err)
		pcap.HandleError(pcap.CapinfoCode, app, err, cb)
		return
	}

	log.Infof("Started capinfo command %v with pid %d", c.capinfoCmd, c.capinfoCmd.Pid())

	termshark.TrackedGo(func() {
		termChan <- c.capinfoCmd.Wait()
	}, Goroutinewg)

	pid = c.capinfoCmd.Pid()
	procChan <- pid

	buf := new(bytes.Buffer)
	buf.ReadFrom(capinfoOut)

	cb.OnCapinfoData(buf.String())

	c.capinfoCancelFn()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
