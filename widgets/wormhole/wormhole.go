// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package wormhole contains a widget that provides the UI for termshark's
// magic-wormhole pcap sending feature.
package wormhole

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/clicktracker"
	"github.com/gcla/gowid/widgets/columns"
	"github.com/gcla/gowid/widgets/divider"
	"github.com/gcla/gowid/widgets/holder"
	"github.com/gcla/gowid/widgets/hpadding"
	"github.com/gcla/gowid/widgets/null"
	"github.com/gcla/gowid/widgets/pile"
	"github.com/gcla/gowid/widgets/progress"
	"github.com/gcla/gowid/widgets/styled"
	"github.com/gcla/gowid/widgets/text"
	"github.com/gcla/termshark/v2"
	"github.com/psanford/wormhole-william/wormhole"
	log "github.com/sirupsen/logrus"
)

//======================================================================

var Goroutinewg *sync.WaitGroup

type state uint

const (
	NotStarted state = 0
	Sending    state = iota
	Complete   state = iota
)

type ErrorFunc func(err error, app gowid.IApp)

type Options struct {
	ErrorHandler        ErrorFunc
	CodeLength          int
	RendezvousURL       string
	TransitRelayAddress string
}

type Widget struct {
	client wormhole.Client
	ctx    context.Context
	cancel context.CancelFunc
	file   *os.File
	code   string
	state  state
	status chan wormhole.SendResult
	opt    Options
	//
	progLock       sync.Mutex
	cancelled      bool
	sentBytes      int64
	totalBytes     int64
	progUpdateChan chan struct{}
	once           sync.Once
	//
	finHolder *holder.Widget
	view1     *holder.Widget
	view2     *holder.Widget
	view3     *holder.Widget
	*holder.Widget
}

var _ gowid.IWidget = (*Widget)(nil)

var fixed gowid.RenderFixed

//======================================================================

func New(filename string, app gowid.IApp, opts ...Options) (*Widget, error) {
	res := &Widget{}
	if err := newWidget(filename, app, res, opts...); err != nil {
		return nil, err
	}
	return res, nil
}

// I set up a helper function because when "Send Again" is clicked, I need to
// reset the struct pointed to by the same *Widget pointer
func newWidget(filename string, app gowid.IApp, w *Widget, opts ...Options) error {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.ErrorHandler == nil {
		opt.ErrorHandler = logError
	}

	switch {
	case opt.CodeLength == 0:
		opt.CodeLength = 2 // default
	case opt.CodeLength < 1:
		opt.CodeLength = 1
	case opt.CodeLength > 8:
		opt.CodeLength = 8
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Could not open pcap file %s: %w", filename, err)
	}

	prog := progress.New(progress.Options{
		Normal:   gowid.MakePaletteRef("progress-default"),
		Complete: gowid.MakePaletteRef("progress-complete"),
	})

	*w = Widget{
		file: file,
		opt:  opt,
	}

	w.client.PassPhraseComponentLength = opt.CodeLength
	if w.opt.RendezvousURL != "" {
		w.client.RendezvousURL = w.opt.RendezvousURL
	}
	if w.opt.TransitRelayAddress != "" {
		w.client.TransitRelayAddress = w.opt.TransitRelayAddress
	}

	w.ctx, w.cancel = context.WithCancel(context.Background())
	code, status, err := w.client.SendFile(
		w.ctx,
		filepath.Base(filename),
		file,
		wormhole.WithProgress(func(sentBytes int64, totalBytes int64) {
			w.progLock.Lock()
			defer w.progLock.Unlock()

			w.sentBytes = sentBytes
			w.totalBytes = totalBytes

			w.once.Do(func() {
				termshark.TrackedGo(func() {
					fn2 := func() {
						app.Run(gowid.RunFunction(func(app gowid.IApp) {
							w.progLock.Lock()
							defer w.progLock.Unlock()

							prog.SetTarget(app, int(w.totalBytes))
							prog.SetProgress(app, int(w.sentBytes))

							if w.Widget == w.view1 {
								w.Widget = w.view2
							}
						}))
					}

					termshark.RunOnDoubleTicker(w.progUpdateChan, fn2,
						time.Duration(500)*time.Millisecond,
						time.Duration(500)*time.Millisecond,
						1)
				}, Goroutinewg)
			})
		}),
	)
	if err != nil {
		return fmt.Errorf("Error initializing wormhole: %w", err)
	}
	w.code = code
	w.status = status
	w.progUpdateChan = make(chan struct{})

	codew := hpadding.New(
		text.New(w.code),
		gowid.HAlignMiddle{},
		gowid.RenderFixed{},
	)

	w.view1 = holder.New(codew)

	stopb := button.New(text.New("X"))

	stopb.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.Close()
	}))

	styledStopB := clicktracker.New(
		styled.NewExt(
			stopb,
			gowid.MakePaletteRef("dialog"),
			gowid.MakePaletteRef("dialog-button"),
		),
	)

	cls := columns.New([]gowid.IContainerWidget{
		&gowid.ContainerWidget{
			IWidget: prog,
			D:       gowid.RenderWithWeight{W: 1},
		},
		&gowid.ContainerWidget{
			IWidget: text.New(" "),
			D:       fixed,
		},
		&gowid.ContainerWidget{
			IWidget: styledStopB,
			D:       fixed,
		},
	})

	w.view2 = holder.New(
		pile.NewFlow(
			codew,
			divider.NewBlank(),
			cls,
		),
	)

	newb := button.New(text.New("Send Again"))
	newb.OnClick(gowid.MakeWidgetCallback("cb", func(app gowid.IApp, w2 gowid.IWidget) {
		w.Close()
		newWidget(filename, app, w, w.opt)
	}))

	w.finHolder = holder.New(null.New())

	w.view3 = holder.New(
		pile.NewFlow(
			hpadding.New(
				w.finHolder,
				gowid.HAlignMiddle{},
				gowid.RenderFixed{},
			),
			divider.NewBlank(),
			hpadding.New(
				styled.NewExt(
					newb,
					gowid.MakePaletteRef("button"),
					gowid.MakePaletteRef("button-focus"),
				),
				gowid.HAlignLeft{},
				gowid.RenderFixed{},
			),
		),
	)

	termshark.TrackedGo(func() {
		// should always terminate because either status will complete or
		// the stop button will call cancel leading to this state change
		select {
		case wres := <-status:
			app.Run(gowid.RunFunction(func(app gowid.IApp) {
				w.progLock.Lock()
				defer w.progLock.Unlock()
				switch {
				case w.cancelled:
					w.finHolder.SetSubWidget(text.New(fmt.Sprintf("%s - cancelled!", w.code)), app)
				case !wres.OK:
					w.finHolder.SetSubWidget(text.New(fmt.Sprintf("%s - error!", w.code)), app)
				default:
					w.finHolder.SetSubWidget(text.New(fmt.Sprintf("%s - done!", w.code)), app)
				}

				w.Widget = w.view3

				// Stop the progress ticket goroutine
				close(w.progUpdateChan)

				if !wres.OK && !w.cancelled {
					w.opt.ErrorHandler(wres.Error, app)
				}

				if w.file != nil {
					w.file.Close() // what would I do with error
					w.file = nil
				}
			}))
		}

	}, Goroutinewg)

	w.Widget = w.view1

	return nil
}

func (w *Widget) CodeLength() int {
	return w.opt.CodeLength
}

func (w *Widget) Close() error {
	w.progLock.Lock()
	defer w.progLock.Unlock()
	w.cancelled = true
	w.cancel()
	return nil
}

//======================================================================

func logError(err error, app gowid.IApp) {
	log.Infof("Error sending via wormhole: %v", err)
}

// XXX-word1-word2-... - max length of word in
// pgp word list is 11
func UpperBoundOnLength(words int) int {
	return 3 + (words * (11 + 1))
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
