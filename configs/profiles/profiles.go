// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package profiles

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/shibukawa/configdir"
	"github.com/spf13/viper"
)

//======================================================================

// The config is accessed by the main goroutine and pcap loading goroutines. So this
// is an attempt to prevent warnings with the -race flag (though they are very likely
// harmless)
var confMutex sync.Mutex

// If this is non-nil, then the user has a profile loaded
var currentName string
var vProfile *viper.Viper
var vDefault *viper.Viper

//======================================================================

func init() {
	vDefault = viper.New()
}

//======================================================================

// First is error, second is warning
func ReadDefaultConfig(dir string) error {
	return readConfig(vDefault, dir, "termshark", true)
}

func readConfig(v *viper.Viper, dir string, base string, createIfNecessary bool) error {
	confMutex.Lock()
	defer confMutex.Unlock()

	var err error

	v.SetConfigName(base) // no need to include file extension - looks for file called termshark.ini for example
	v.AddConfigPath(dir)

	fp := filepath.Join(dir, fmt.Sprintf("%s.toml", base))
	if createIfNecessary {
		var f *os.File
		if f, err = os.OpenFile(fp, os.O_RDONLY|os.O_CREATE, 0666); err == nil {
			f.Close()
		}
	}

	// We managed anyway - so don't alarm the user
	if v.ReadInConfig() == nil {
		err = nil
	} else if err != nil {
		err = fmt.Errorf("Profile %s not found. (%w)", fp, err)
	} else {
		err = fmt.Errorf("Profile %s not found.", fp)
	}

	return err
}

func Default() *viper.Viper {
	return vDefault
}

func Current() *viper.Viper {
	if vProfile != nil {
		return vProfile
	}
	return Default()
}

func ConfKeyExists(name string) bool {
	return ConfKeyExistsIn(Current(), name) || ConfKeyExistsIn(Default(), name)
}

func ConfKeyExistsIn(v *viper.Viper, name string) bool {
	return v.Get(name) != nil
}

func ConfString(name string, def string) string {
	return ConfStringFrom(Current(), Default(), name, def)
}

func ConfStringFrom(v *viper.Viper, vd *viper.Viper, name string, def string) string {
	confMutex.Lock()
	defer confMutex.Unlock()
	// Use GetString because viper will not allow deletion of keys; so I always
	// use the assumption that "" is the same as unset for a string key; then
	// I can fallback to the default map if the requested key's value is either ""
	// or missing
	if v != nil && v.GetString(name) != "" {
		return v.GetString(name)
	} else if vd.GetString(name) != "" {
		return vd.GetString(name)
	} else {
		return def
	}
}

func SetConf(name string, val interface{}) {
	SetConfIn(Current(), name, val)
}

func SetConfIn(v *viper.Viper, name string, val interface{}) {
	confMutex.Lock()
	defer confMutex.Unlock()
	v.Set(name, val)
	v.WriteConfig()
}

func ConfStrings(name string) []string {
	return confStrings(Current(), Default(), name)
}

func confStrings(v *viper.Viper, vd *viper.Viper, name string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v != nil && ConfKeyExistsIn(v, name) {
		return v.GetStringSlice(name)
	} else {
		return vd.GetStringSlice(name)
	}
}

func DeleteConf(name string) {
	deleteConf(Current(), name)
}

func deleteConf(v *viper.Viper, name string) {
	confMutex.Lock()
	defer confMutex.Unlock()
	v.Set(name, "")
	v.WriteConfig()
}

func ConfInt(name string, def int) int {
	return confInt(Current(), Default(), name, def)
}

func confInt(v *viper.Viper, vd *viper.Viper, name string, def int) int {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v != nil && v.Get(name) != nil {
		return v.GetInt(name)
	} else if vd != nil && vd.Get(name) != nil {
		return vd.GetInt(name)
	} else {
		return def
	}
}

func ConfBool(name string, def ...bool) bool {
	return confBool(vProfile, vDefault, name, def...)
}

func confBool(v *viper.Viper, vd *viper.Viper, name string, def ...bool) bool {
	confMutex.Lock()
	defer confMutex.Unlock()
	if v != nil && v.Get(name) != nil {
		return v.GetBool(name)
	} else if vd != nil && vd.Get(name) != nil {
		return vd.GetBool(name)
	} else {
		if len(def) > 0 {
			return def[0]
		} else {
			return false
		}
	}
}

func ConfStringSlice(name string, def []string) []string {
	return ConfStringSliceFrom(vProfile, vDefault, name, def)
}

func ConfStringSliceFrom(v *viper.Viper, vd *viper.Viper, name string, def []string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	var res []string
	if v != nil {
		res = v.GetStringSlice(name)
	}
	if res == nil && vd != nil {
		res = vd.GetStringSlice(name)
	}
	if res == nil {
		res = def
	}
	return res
}

func WriteConfigAs(name string) error {
	return writeConfigAs(Current(), name)
}

func writeConfigAs(v *viper.Viper, name string) error {
	return v.WriteConfigAs(name)
}

func profilesDir() (string, error) {
	stdConf := configdir.New("", "termshark")
	conf := stdConf.QueryFolderContainsFile("profiles")
	if conf == nil {
		return "", fmt.Errorf("Could not find profiles dir.")
	}
	dirs := stdConf.QueryFolders(configdir.Global)
	return filepath.Join(dirs[0].Path, "profiles"), nil
}

func CopyToAndUse(name string) error {
	if Default() == Current() {
		vProfile = viper.New()
	}

	dir, err := profilesDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, name)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, 0777)
		if err != nil {
			return fmt.Errorf("Unexpected error making dir %s: %v", dir, err)
		}
	}

	vProfile.SetConfigFile(filepath.Join(dir, "termshark.toml"))
	vProfile.WriteConfig()

	return Use(name)
}

func CurrentName() string {
	if currentName == "" {
		return "default"
	}
	return currentName
}

func AllNames() []string {
	res := AllNonDefaultNames()
	return append(res, "default")
}

func AllNonDefaultNames() []string {
	matches := make([]string, 0)

	profPath, err := profilesDir()
	if err != nil {
		return matches
	}

	files, err := ioutil.ReadDir(profPath)
	if err == nil {
		for _, file := range files {
			if file.Name() != "default" {
				if _, err := os.Stat(filepath.Join(profPath, file.Name(), "termshark.toml")); err == nil {
					matches = append(matches, file.Name())
				}
			}
		}
	}

	return matches
}

func Delete(name string) error {
	dir, err := profilesDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, name)

	err = os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("Unexpected error deleting profile dir %s: %v", dir, err)
	}

	return nil
}

func Use(name string) error {
	// Go back to default - so no overriding profile
	if name == "" || name == "default" {
		confMutex.Lock()
		defer confMutex.Unlock()
		vProfile = nil
		currentName = "default"
		return nil
	}

	vNew := viper.New()

	dir, err := profilesDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, name)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, 0777)
		if err != nil {
			return fmt.Errorf("Unexpected error making dir %s: %v", dir, err)
		}
	}

	if err := readConfig(vNew, dir, "termshark", false); err != nil {
		return err
	}

	vProfile = vNew
	currentName = name
	return nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
