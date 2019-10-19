// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

//======================================================================

var Goroutinewg *sync.WaitGroup

type ConfigWatcher struct {
	watcher *fsnotify.Watcher
	change  chan struct{}
	closech chan struct{}
	closed  bool
}

func NewConfigWatcher() (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}

	change := make(chan struct{})
	closech := make(chan struct{})

	res := &ConfigWatcher{
		change:  change,
		closech: closech,
	}

	TrackedGo(func() {
		defer func() {
			close(change)
		}()
	Loop:
		for {
			var evch <-chan fsnotify.Event
			var errch <-chan error
			if !res.closed {
				evch = watcher.Events
				errch = watcher.Errors
			}

			select {
			// watch for events
			case <-evch:
				res.change <- struct{}{}

			case err := <-errch:
				log.Debugf("Error from config watcher: %v", err)

			case <-closech:
				break Loop
			}
		}
	}, Goroutinewg)

	if err := watcher.Add(ConfFile("termshark.toml")); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	res.watcher = watcher

	return res, nil
}

func (c *ConfigWatcher) Close() error {
	// Close the watcher first. This prevents a dossible deadlock
	// - termshark shuts down, exiting select loop that processes c.change channel
	// - an event from the watcher occurs, the goroutine above writes to c.change and blocks
	// - the deferred call to Close() here is made, and deadlocks on writing to c.close
	//
	res := c.watcher.Close()
	c.closed = true

	// drain the change channel to ensure the goroutine above can process the close. This
	// is safe because I know, at this point, there are no other readers because termshark
	// has exited its select loop.
	TrackedGo(func() {
		// This might block because the goroutine above might not be blocked sending
		// to c.change. But then that means the goroutine's for loop above will terminate,
		// c.change will be closed, and then this goroutine will end. If the above
		// goroutine is blocked sending to c.change, then this will drain that value,
		// and again the goroutine above will end.
		<-c.change
	})

	c.closech <- struct{}{}
	return res
}

func (c *ConfigWatcher) ConfigChanged() <-chan struct{} {
	return c.change
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
