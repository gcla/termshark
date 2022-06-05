// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/viper"
)

//======================================================================

// The config is accessed by the main goroutine and pcap loading goroutines. So this
// is an attempt to prevent warnings with the -race flag (though they are very likely
// harmless)
var confMutex sync.Mutex

// If this is non-nil, then the user has a profile loaded
var vProfile *viper.Viper
var vDefault *viper.Viper

//======================================================================

func init() {
	vDefault = viper.New()
	vProfile = viper.New()
}

//======================================================================

// First is error, second is warning
func ReadDefaultConfig(dir string) error {
	return readConfig(vDefault, dir, "termshark")
}

func readConfig(v *viper.Viper, dir string, base string) error {
	confMutex.Lock()
	defer confMutex.Unlock()

	var err error

	v.SetConfigName(base) // no need to include file extension - looks for file called termshark.ini for example
	v.AddConfigPath(dir)

	fp := filepath.Join(dir, fmt.Sprintf("%s.toml", base))
	if f, err2 := os.OpenFile(fp, os.O_RDONLY|os.O_CREATE, 0666); err2 != nil {
		err = fmt.Errorf("Warning: could not create initial config file: %w", err2)
	} else {
		f.Close()
	}

	err = v.ReadInConfig()
	if err != nil {
		err = fmt.Errorf("Warning: config file %s not found...", fp)
	}

	return err
}

func ConfKeyExists(name string) bool {
	return confKeyExists(vDefault, name)
}

func confKeyExists(v *viper.Viper, name string) bool {
	return v.Get(name) != nil
}

func ConfString(name string, def string) string {
	return confString(vDefault, name, def)
}

func confString(v *viper.Viper, name string, def string) string {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v.Get(name) != nil {
		return v.GetString(name)
	} else {
		return def
	}
}

func SetConf(name string, val interface{}) {
	setConf(vDefault, name, val)
}

func setConf(v *viper.Viper, name string, val interface{}) {
	confMutex.Lock()
	defer confMutex.Unlock()
	v.Set(name, val)
	v.WriteConfig()
}

func ConfStrings(name string) []string {
	return confStrings(vDefault, name)
}

func confStrings(v *viper.Viper, name string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	return v.GetStringSlice(name)
}

func DeleteConf(name string) {
	deleteConf(vDefault, name)
}

func deleteConf(v *viper.Viper, name string) {
	confMutex.Lock()
	defer confMutex.Unlock()
	v.Set(name, "")
	v.WriteConfig()
}

func ConfInt(name string, def int) int {
	return confInt(vDefault, name, def)
}

func confInt(v *viper.Viper, name string, def int) int {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v.Get(name) != nil {
		return v.GetInt(name)
	} else {
		return def
	}
}

func ConfBool(name string, def ...bool) bool {
	return confBool(vDefault, name, def...)
}

func confBool(v *viper.Viper, name string, def ...bool) bool {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v.Get(name) != nil {
		return v.GetBool(name)
	} else {
		if len(def) > 0 {
			return def[0]
		} else {
			return false
		}
	}
}

func ConfStringSlice(name string, def []string) []string {
	return confStringSlice(vDefault, name, def)
}

func confStringSlice(v *viper.Viper, name string, def []string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	res := v.GetStringSlice(name)
	if res == nil {
		res = def
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
