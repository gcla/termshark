// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
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
	"github.com/gcla/termshark/v2/pcap"
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
	OnData(data string, closeMe chan struct{})
	AfterDataEnd(success bool, closeMe chan<- struct{})
}

func (c *Loader) StartLoad(pcap string, convs []string, filter string, abs bool, resolve bool, app gowid.IApp, cb IConvsCallbacks) {
	termshark.TrackedGo(func() {
		c.loadConvAsync(pcap, convs, filter, abs, resolve, app, cb)
	}, Goroutinewg)
}

func (c *Loader) loadConvAsync(pcapf string, convs []string, filter string, abs bool, resolve bool, app gowid.IApp, cb IConvsCallbacks) {
	c.convsCtx, c.convsCancelFn = context.WithCancel(c.mainCtx)

	c.convsCmd = c.cmds.Convs(pcapf, convs, filter, abs, resolve)

	convsOut, err := c.convsCmd.StdoutReader()
	if err != nil {
		pcap.HandleError(err, cb)
		return
	}

	defer func() {
		ch := make(chan struct{})
		cb.AfterDataEnd(true, ch)
		<-ch
	}()

	pcap.HandleBegin(cb)
	defer func() {
		pcap.HandleEnd(cb)
	}()

	err = c.convsCmd.Start()
	if err != nil {
		err = fmt.Errorf("Error starting %v: %v", c.convsCmd, err)
		pcap.HandleError(err, cb)
		return
	}

	log.Infof("Started command %v with pid %d", c.convsCmd, c.convsCmd.Pid())

	procWaitChan := make(chan error, 1)

	defer func() {
		procWaitChan <- c.convsCmd.Wait()
	}()

	termshark.TrackedGo(func() {
		var err error
		cancelled := c.convsCtx.Done()
	loop:
		for {
			select {
			case <-cancelled:
				err := termshark.KillIfPossible(c.convsCmd)
				if err != nil {
					log.Infof("Did not kill tshark conv process: %v", err)
				}
				cancelled = nil
			case err = <-procWaitChan:
				if !c.SuppressErrors && err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						cerr := gowid.WithKVs(termshark.BadCommand, map[string]interface{}{
							"command": c.convsCmd.String(),
							"error":   err,
						})
						pcap.HandleError(cerr, cb)
					}
				}
				break loop
			}
		}
		c.convsCtx = nil
		c.convsCancelFn = nil
	}, Goroutinewg)

	buf := new(bytes.Buffer)
	buf.ReadFrom(convsOut)

	ch := make(chan struct{})
	cb.OnData(buf.String(), ch)
	<-ch
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
