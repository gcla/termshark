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
	close   chan struct{}
}

func NewConfigWatcher() (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}

	change := make(chan struct{})
	close := make(chan struct{})

	res := &ConfigWatcher{
		change: change,
		close:  close,
	}

	TrackedGo(func() {
	Loop:
		for {
			select {
			// watch for events
			case <-watcher.Events:
				res.change <- struct{}{}

			case err := <-watcher.Errors:
				log.Debugf("Error from config watcher: %v", err)

			case <-close:
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

	// drain the change channel to ensure the goroutine above can process the close. This
	// is safe because I know, at this point, there are no other readers because termshark
	// has exited its select loop.
	for len(c.change) > 0 {
		<-c.change
	}

	c.close <- struct{}{}
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
