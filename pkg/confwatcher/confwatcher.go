// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package confwatcher

import (
	"os"
	"sync"

	"github.com/gcla/termshark/v2"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

//======================================================================

type ConfigWatcher struct {
	watcher   *fsnotify.Watcher
	change    chan struct{}
	closech   chan struct{}
	closeWait sync.WaitGroup
}

func New() (*ConfigWatcher, error) {
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

	res.closeWait.Add(1)

	termshark.TrackedGo(func() {
		defer func() {
			res.watcher.Close()
			close(change)
			res.closeWait.Done()
		}()
	Loop:
		for {
			select {
			case <-watcher.Events:
				res.change <- struct{}{}

			case err := <-watcher.Errors:
				log.Debugf("Error from config watcher: %v", err)

			case <-closech:
				break Loop
			}
		}
	}, Goroutinewg)

	if err := watcher.Add(termshark.ConfFile("termshark.toml")); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	res.watcher = watcher

	return res, nil
}

func (c *ConfigWatcher) Close() {
	// drain the change channel to ensure the goroutine above can process the close. This
	// is safe because I know, at this point, there are no other readers because termshark
	// has exited its select loop.
	termshark.TrackedGo(func() {
		// This might block because the goroutine above might not be blocked sending
		// to c.change. But then that means the goroutine's for loop above will terminate,
		// c.change will be closed, and then this goroutine will end. If the above
		// goroutine is blocked sending to c.change, then this will drain that value,
		// and again the goroutine above will end.
		<-c.change
	}, Goroutinewg)

	c.closech <- struct{}{}
	c.closeWait.Wait()
}

func (c *ConfigWatcher) ConfigChanged() <-chan struct{} {
	return c.change
}

//======================================================================

var Goroutinewg *sync.WaitGroup

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
