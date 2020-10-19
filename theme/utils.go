// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// package theme provides utilities for customizing the styling of termshark.
package theme

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gcla/gowid"
	"github.com/rakyll/statik/fs"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	_ "github.com/gcla/termshark/v2/assets/statik"
)

//======================================================================

type Layer int

const (
	Foreground Layer = 0
	Background Layer = iota
)

var theme *viper.Viper

// MakeColorSafe extends gowid's MakeColorSafe function, prefering to interpret
// its string argument as a toml file config key lookup first; if this fails, then
// fall back to gowid.MakeColorSafe, which will then read colors as urwid color names,
// #-prefixed hex digits, grayscales, etc.
func MakeColorSafe(s string, l Layer) (gowid.Color, error) {
	loops := 10
	cur := s
	if theme != nil {
		for {
			next := theme.GetString(cur)
			if next != "" {
				cur = next
			} else {
				next := theme.GetStringSlice(cur)
				if next == nil || len(next) != 2 {
					break
				} else {
					cur = next[l]
				}
			}
			loops -= 1
			if loops == 0 {
				break
			}
		}
	}
	col, err := gowid.MakeColorSafe(cur)
	if err == nil {
		return gowid.Color{IColor: col, Id: s}, nil
	}
	return gowid.MakeColorSafe(s)
}

// Load will set the package-level theme object to a viper object representing the
// toml file either (a) read from disk, or failing that (b) built-in to termshark.
// Disk themes are prefered and take precedence.
func Load(name string, app gowid.IApp) error {
	var err error

	theme = viper.New()
	defer func() {
		if err != nil {
			theme = nil
		}
	}()

	theme.SetConfigType("toml")
	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Global)

	var mode string
	switch app.GetColorMode() {
	case gowid.Mode24BitColors:
		mode = "truecolor"
	case gowid.Mode256Colors:
		mode = "256"
	default:
		mode = "16"
	}

	// If there's not a truecolor theme, we assume the user wants the best alternative to be loaded,
	// and if a terminal has truecolor support, it'll surely have 256-color support.
	modes := []string{mode}
	if mode == "truecolor" {
		modes = append(modes, "256")
	}

	for _, m := range modes {
		// Prefer to load from disk
		themeFileName := filepath.Join(dirs[0].Path, "themes", fmt.Sprintf("%s-%s.toml", name, m))
		log.Infof("Trying to load user theme %s", themeFileName)
		var file io.ReadCloser
		file, err = os.Open(themeFileName)
		if err == nil {
			defer file.Close()
			log.Infof("Loaded user theme %s", themeFileName)
			return theme.ReadConfig(file)
		}
	}

	// Fall back to built-in themes
	statikFS, err := fs.New()
	if err != nil {
		return fmt.Errorf("in mode %v: %v", app.GetColorMode(), err)
	}

	for _, m := range modes {
		themeFileName := filepath.Join("/themes", fmt.Sprintf("%s-%s.toml", name, m))
		log.Infof("Trying to load built-in theme %s", themeFileName)
		var file io.ReadCloser
		file, err = statikFS.Open(themeFileName)
		if err == nil {
			defer file.Close()
			log.Infof("Loaded built-in theme %s", themeFileName)
			return theme.ReadConfig(file)
		}
	}

	return err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
