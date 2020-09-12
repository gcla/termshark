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

// Clear resets the package-level theme object. Next time ui.SetupColors is called,
// the theme-connected colors won't be found, and termshark will fall back to its
// programmed default colors.
func Clear() {
	theme = nil
}

// Load will set the package-level theme object to a viper object representing the
// toml file either (a) read from disk, or failing that (b) built-in to termshark.
// Disk themes are prefered and take precedence.
func Load(name string) error {
	theme = viper.New()
	theme.SetConfigType("toml")
	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Global)

	// Prefer to load from disk
	themeFileName := filepath.Join(dirs[0].Path, "themes", fmt.Sprintf("%s.toml", name))

	var file io.ReadCloser
	var err error

	file, err = os.Open(themeFileName)
	if err == nil {
		defer file.Close()
		return theme.ReadConfig(file)
	}

	// Fall back to built-in themes
	statikFS, err := fs.New()
	if err != nil {
		return err
	}

	file, err = statikFS.Open(filepath.Join("/themes", fmt.Sprintf("%s.toml", name)))
	if err != nil {
		return err
	}
	defer file.Close()

	return theme.ReadConfig(file)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
