// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package wiresharkcfg

import (
	"fmt"
	"os"
	"path"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/shibukawa/configdir"
)

//======================================================================

var NotFoundError = fmt.Errorf("Could not find wireshark preferences")
var NotParsedError = fmt.Errorf("Could not parse wireshark preferences")

type Config struct {
	Strings map[string]string
	Lists   map[string][]string
}

func NewDefault() (*Config, error) {
	// See https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html
	// Wireshark had a ~/.wireshark directory before adopting XDG
	tryXDG := true
	cpath, err := homedir.Expand("~/.wireshark/preferences")
	if err == nil {
		_, err = os.Stat(cpath)
		if err == nil {
			tryXDG = false
		}
	}
	if tryXDG {
		stdConf := configdir.New("", "wireshark")
		dirs := stdConf.QueryFolders(configdir.All)
		cpath = path.Join(dirs[0].Path, "preferences")
		_, err = os.Stat(cpath)
		if os.IsNotExist(err) {
			return nil, err
		}
	}

	res := &Config{}
	err = res.PopulateFrom(cpath)
	return res, err
}

func (c *Config) PopulateFrom(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	parsed, err := ParseReader("", file)
	if err != nil {
		return err
	}

	*c = *(parsed.(*Config))
	return nil
}

func (c *Config) GetList(key string) []string {
	if c == nil {
		return nil
	}
	if val, ok := c.Lists[key]; ok {
		return val
	}
	return nil
}

func (c *Config) ColumnFormat() []string {
	return c.GetList("gui.column.format")
}

func (c *Config) merge(other *Config) {
	for k, v := range other.Strings {
		c.Strings[k] = v
	}
	for k, v := range other.Lists {
		c.Lists[k] = v
	}
}

func (c *Config) String() string {
	res := make([]string, 0, len(c.Strings)+len(c.Lists))
	for k, v := range c.Strings {
		res = append(res, fmt.Sprintf("%s: %s", k, v))
	}
	for k, v := range c.Lists {
		v2 := strings.Join(v, ", ")
		res = append(res, fmt.Sprintf("%s: %s", k, v2))
	}
	return strings.Join(res, "\n")
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 110
// End:
