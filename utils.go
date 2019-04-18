// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/gcla/gowid"
	"github.com/blang/semver"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//======================================================================

type BadStateError struct{}

var _ error = BadStateError{}

func (e BadStateError) Error() string {
	return "Bad state"
}

var BadState = BadStateError{}

//======================================================================

func IsCommandInPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func DirOfPathCommandUnsafe(bin string) string {
	d, err := DirOfPathCommand(bin)
	if err != nil {
		panic(err)
	}
	return d
}

func DirOfPathCommand(bin string) (string, error) {
	return exec.LookPath(bin)
}

func TSharkBin() string {
	return ConfString("main.tshark", "tshark")
}

func DumpcapBin() string {
	return ConfString("main.dumpcap", "dumpcap")
}

func TailCommand() []string {
	def := []string{"tail", "-f", "-c", "+0"}
	if runtime.GOOS == "windows" {
		def[0] = "c:\\cygwin64\\bin\\tail.exe"
	}
	return ConfStringSlice("main.tail-command", def)
}

func ConfString(name string, def string) string {
	if viper.Get(name) != nil {
		return viper.GetString(name)
	} else {
		return def
	}
}

func ConfInt(name string, def int) int {
	if viper.Get(name) != nil {
		return viper.GetInt(name)
	} else {
		return def
	}
}

var TSharkVersionUnknown = fmt.Errorf("Could not determine version of tshark")

func TSharkVersionFromOutput(output string) (semver.Version, error) {
	var ver = regexp.MustCompile(`^TShark .*?(\d+\.\d+\.\d+)`)
	res := ver.FindStringSubmatch(output)

	if len(res) > 0 {
		if v, err := semver.Make(res[1]); err == nil {
			return v, nil
		} else {
			return semver.Version{}, err
		}
	}

	return semver.Version{}, errors.WithStack(TSharkVersionUnknown)
}

func TSharkVersion(tshark string) (semver.Version, error) {
	cmd := exec.Command(tshark, "--version")
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	cmd.Run() // don't check error - older versions return error code 1. Just search output.
	output := cmdOutput.Bytes()

	return TSharkVersionFromOutput(string(output))
}

func RunForExitCode(prog string, args ...string) (int, error) {
	var err error
	exitCode := -1 // default bad
	cmd := exec.Command(prog, args...)
	err = cmd.Run()
	if err != nil {
		if exerr, ok := err.(*exec.ExitError); ok {
			ws := exerr.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		}
	} else {
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}

	return exitCode, err
}

func ConfStringSlice(name string, def []string) []string {
	res := viper.GetStringSlice(name)
	if res == nil {
		res = def
	}
	return res
}

func ConfFile(file string) string {
	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Global)
	return path.Join(dirs[0].Path, file)
}

func CacheFile(bin string) string {
	return filepath.Join(CacheDir(), bin)
}

func CacheDir() string {
	stdConf := configdir.New("", "termshark")
	dirs := stdConf.QueryFolders(configdir.Cache)
	return dirs[0].Path
}

func RemoveFromStringSlice(pcap string, comps []string) []string {
	var newcomps []string
	for _, v := range comps {
		if v == pcap {
			continue
		} else {
			newcomps = append(newcomps, v)
		}
	}
	newcomps = append([]string{pcap}, newcomps...)
	return newcomps
}

const magicMicroseconds = 0xA1B2C3D4
const versionMajor = 2
const versionMinor = 4
const dlt_en10mb = 1

func WriteEmptyPcap(filename string) error {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	// bytes 8:12 stay 0 (timezone = UTC)
	// bytes 12:16 stay 0 (sigfigs is always set to zero, according to
	//   http://wiki.wireshark.org/Development/LibpcapFileFormat
	binary.LittleEndian.PutUint32(buf[16:20], 10000)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(dlt_en10mb))

	err := ioutil.WriteFile(filename, buf[:], 0644)

	return err
}

func FileNewerThan(f1, f2 string) (bool, error) {
	file1, err := os.Open(f1)
	if err != nil {
		return false, err
	}
	defer file1.Close()
	file2, err := os.Open(f2)
	if err != nil {
		return false, err
	}
	defer file2.Close()
	f1s, err := file1.Stat()
	if err != nil {
		return false, err
	}
	f2s, err := file2.Stat()
	if err != nil {
		return false, err
	}
	return f1s.ModTime().After(f2s.ModTime()), nil
}

func ReadGob(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err == nil {
		defer file.Close()
		var gr io.Reader
		gr, err = gzip.NewReader(file)
		if err != nil {
			return err
		}
		decoder := gob.NewDecoder(gr)
		err = decoder.Decode(object)
	}
	return err
}

func WriteGob(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err == nil {
		defer file.Close()
		gzipper := gzip.NewWriter(file)
		defer gzipper.Close()
		encoder := gob.NewEncoder(gzipper)
		err = encoder.Encode(object)
	}
	return err
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Must succeed - use on internal templates
func TemplateToString(tmpl *template.Template, name string, data interface{}) string {
	var res bytes.Buffer
	if err := tmpl.ExecuteTemplate(&res, name, data); err != nil {
		log.Fatal(err)
	}

	return res.String()
}

func StringIsArgPrefixOf(a string, list []string) bool {
	for _, b := range list {
		if strings.HasPrefix(a, fmt.Sprintf("%s=", b)) {
			return true
		}
	}
	return false
}

func RunOnDoubleTicker(ch <-chan struct{}, fn func(), dur1 time.Duration, dur2 time.Duration, loops int) {

	ticker := time.NewTicker(dur1)
	counter := 0
Loop:
	for {
		select {
		case <-ticker.C:
			fn()
			counter++
			if counter == loops {
				ticker.Stop()
				ticker = time.NewTicker(dur2)
			}
		case <-ch:
			ticker.Stop()
			break Loop
		}
	}
}

func TrackedGo(fn func(), wgs ...*sync.WaitGroup) {
	for _, wg := range wgs {
		wg.Add(1)
	}
	go func() {
		for _, wg := range wgs {
			defer wg.Done()
		}
		fn()
	}()
}

type IProcess interface {
	Kill() error
	Pid() int
}

func KillIfPossible(p IProcess) error {
	if p == nil {
		return nil
	}
	err := p.Kill()
	return err
}

func SafePid(p IProcess) int {
	if p == nil {
		return -1
	}
	return p.Pid()
}

//======================================================================

// From http://blog.kamilkisiel.net/blog/2012/07/05/using-the-go-regexp-package/
//
type tsregexp struct {
	*regexp.Regexp
}

func (r *tsregexp) FindStringSubmatchMap(s string) map[string]string {
	captures := make(map[string]string)

	match := r.FindStringSubmatch(s)
	if match == nil {
		return captures
	}

	for i, name := range r.SubexpNames() {
		if i == 0 {
			continue
		}
		captures[name] = match[i]
	}

	return captures
}

var flagRE = tsregexp{regexp.MustCompile(`--tshark-(?P<flag>[a-zA-Z0-9])=(?P<val>.+)`)}

func ConvertArgToTShark(arg string) (string, string, bool) {
	matches := flagRE.FindStringSubmatchMap(arg)
	if flag, ok := matches["flag"]; ok {
		if val, ok := matches["val"]; ok {
			if val == "false" {
				return "", "", false
			} else if val == "true" {
				return flag, "", true
			} else {
				return flag, val, true
			}
		}
	}
	return "", "", false
}

//======================================================================

var UnexpectedOutput = fmt.Errorf("Unexpected output")

// Use tshark's output, becauses the indices can then be used to select
// an interface to sniff on, and net.Interfaces returns the interfaces in
// a different order.
func Interfaces() ([]string, error) {
	cmd := exec.Command(TSharkBin(), "-D")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return interfacesFrom(bytes.NewReader(out))
}

func interfacesFrom(reader io.Reader) ([]string, error) {
	res := make([]string, 0, 20)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		pieces := strings.Fields(line)
		if len(pieces) < 2 {
			return nil, gowid.WithKVs(UnexpectedOutput, map[string]interface{}{"Output": line})
		}
		res = append(res, pieces[1])
	}

	return res, nil
}

//======================================================================

type pdmlany struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Comment string     `xml:",comment"`
	Nested  []*pdmlany `xml:",any"`
	//Content string     `xml:",chardata"`
}

// IndentPdml reindents XML, disregarding content between tags (because we knoe
// PDML doesn't use that capability of XML)
func IndentPdml(in io.Reader, out io.Writer) error {
	decoder := xml.NewDecoder(in)

	n := pdmlany{}
	if err := decoder.Decode(&n); err != nil {
		return err
	}

	b, err := xml.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	out.Write(fixNewlines(b))
	return nil
}

func fixNewlines(unix []byte) []byte {
	if runtime.GOOS != "windows" {
		return unix
	}

	return bytes.Replace(unix, []byte{'\n'}, []byte{'\r', '\n'}, -1)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
