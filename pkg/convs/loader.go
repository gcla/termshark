// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package convs

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
	Convs(pcapfile string, convs []string, filter string, abs bool, resolve bool) pcap.IPcapCommand
}

type commands struct{}

func MakeCommands() commands {
	return commands{}
}

var _ ILoaderCmds = commands{}

func (c commands) Convs(pcapfile string, convs []string, filter string, abs bool, resolve bool) pcap.IPcapCommand {
	args := []string{"-q", "-r", pcapfile}
	if abs {
		args = append(args, "-t", "a")
	}
	if !resolve {
		args = append(args, "-n")
	}
	for _, conv := range convs {
		args = append(args, "-z", fmt.Sprintf("conv,%s", conv))
		if filter != "" {
			args[len(args)-1] = fmt.Sprintf("%s,%s", args[len(args)-1], filter)
		}
	}
	return &pcap.Command{
		Cmd: exec.Command(termshark.TSharkBin(), args...),
	}
}

//======================================================================

type Loader struct {
	cmds ILoaderCmds

	SuppressErrors bool // if true, don't report process errors e.g. at shutdown

	mainCtx      context.Context // cancelling this cancels the dependent contexts
	mainCancelFn context.CancelFunc

	convsCtx      context.Context
	convsCancelFn context.CancelFunc

	convsCmd pcap.IPcapCommand
}

func NewLoader(cmds ILoaderCmds, ctx context.Context) *Loader {
	res := &Loader{
		cmds: cmds,
	}
	res.mainCtx, res.mainCancelFn = context.WithCancel(ctx)
	return res
}

func (c *Loader) StopLoad() {
	if c.convsCancelFn != nil {
		c.convsCancelFn()
	}
}

//======================================================================

type IConvsCallbacks interface {
	OnData(data string)
	AfterDataEnd(success bool)
}

func (c *Loader) StartLoad(pcap string, convs []string, filter string, abs bool, resolve bool, app gowid.IApp, cb IConvsCallbacks) {
	termshark.TrackedGo(func() {
		c.loadConvAsync(pcap, convs, filter, abs, resolve, app, cb)
	}, Goroutinewg)
}

func (c *Loader) loadConvAsync(pcapf string, convs []string, filter string, abs bool, resolve bool, app gowid.IApp, cb IConvsCallbacks) {
	c.convsCtx, c.convsCancelFn = context.WithCancel(c.mainCtx)

	procChan := make(chan int)
	pid := 0

	defer func() {
		if pid == 0 {
			close(procChan)
		}
	}()

	c.convsCmd = c.cmds.Convs(pcapf, convs, filter, abs, resolve)

	termChan := make(chan error)

	termshark.TrackedGo(func() {
		var err error
		cmd := c.convsCmd
		cancelledChan := c.convsCtx.Done()
		procChan := procChan
		state := pcap.NotStarted

		kill := func() {
			err := termshark.KillIfPossible(cmd)
			if err != nil {
				log.Infof("Did not kill tshark conv process: %v", err)
			}
		}

	loop:
		for {
			select {
			case err = <-termChan:
				state = pcap.Terminated
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						pcap.HandleError(pcap.ConvCode, app, pcap.MakeUsefulError(c.convsCmd, err), cb)
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

	convsOut, err := c.convsCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(pcap.ConvCode, app, err, cb)
		return
	}

	defer func() {
		cb.AfterDataEnd(true)
	}()

	app.Run(gowid.RunFunction(func(app gowid.IApp) {
		pcap.HandleBegin(pcap.ConvCode, app, cb)
	}))
	defer func() {
		app.Run(gowid.RunFunction(func(app gowid.IApp) {
			pcap.HandleEnd(pcap.ConvCode, app, cb)
		}))
	}()

	err = c.convsCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting %v: %v", c.convsCmd, err)
		pcap.HandleError(pcap.ConvCode, app, err, cb)
		return
	}

	log.Infof("Started command %v with pid %d", c.convsCmd, c.convsCmd.Pid())

	termshark.TrackedGo(func() {
		termChan <- c.convsCmd.Wait()
	}, Goroutinewg)

	pid = c.convsCmd.Pid()
	procChan <- pid

	buf := new(bytes.Buffer)
	buf.ReadFrom(convsOut)

	cb.OnData(buf.String())

	c.convsCancelFn()
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
