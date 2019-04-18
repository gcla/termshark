// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify.v1"
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
	c.close <- struct{}{}
	return c.watcher.Close()
}

func (c *ConfigWatcher) ConfigChanged() <-chan struct{} {
	return c.change
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
