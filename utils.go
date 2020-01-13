// Copyright 2019-2020 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/blang/semver"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/termshark/v2/system"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/tevino/abool"
)

//======================================================================

type BadStateError struct{}

var _ error = BadStateError{}

func (e BadStateError) Error() string {
	return "Bad state"
}

var BadState = BadStateError{}

//======================================================================

type BadCommandError struct{}

var _ error = BadCommandError{}

func (e BadCommandError) Error() string {
	return "Error running command"
}

var BadCommand = BadCommandError{}

//======================================================================

type ConfigError struct{}

var _ error = ConfigError{}

func (e ConfigError) Error() string {
	return "Configuration error"
}

var ConfigErr = ConfigError{}

//======================================================================

type InternalError struct{}

var _ error = InternalError{}

func (e InternalError) Error() string {
	return "Internal error"
}

var InternalErr = InternalError{}

//======================================================================

var (
	UserGuideURL string = "https://termshark.io/userguide"
	FAQURL       string = "https://termshark.io/faq"
)

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

//======================================================================

// The config is accessed by the main goroutine and pcap loading goroutines. So this
// is an attempt to prevent warnings with the -race flag (though they are very likely
// harmless)
var confMutex sync.Mutex

func ConfString(name string, def string) string {
	confMutex.Lock()
	defer confMutex.Unlock()
	if viper.Get(name) != nil {
		return viper.GetString(name)
	} else {
		return def
	}
}

func SetConf(name string, val interface{}) {
	confMutex.Lock()
	defer confMutex.Unlock()
	viper.Set(name, val)
	viper.WriteConfig()
}

func ConfStrings(name string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	return viper.GetStringSlice(name)
}

func DeleteConf(name string) {
	confMutex.Lock()
	defer confMutex.Unlock()
	delete(viper.Get("main").(map[string]interface{}), name)
	viper.WriteConfig()
}

func ConfInt(name string, def int) int {
	confMutex.Lock()
	defer confMutex.Unlock()
	if viper.Get(name) != nil {
		return viper.GetInt(name)
	} else {
		return def
	}
}

func ConfBool(name string, def ...bool) bool {
	confMutex.Lock()
	defer confMutex.Unlock()
	if viper.Get(name) != nil {
		return viper.GetBool(name)
	} else {
		if len(def) > 0 {
			return def[0]
		} else {
			return false
		}
	}
}

func ConfStringSlice(name string, def []string) []string {
	confMutex.Lock()
	defer confMutex.Unlock()
	res := viper.GetStringSlice(name)
	if res == nil {
		res = def
	}
	return res
}

//======================================================================

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

// Depends on empty.pcap being present
func TSharkSupportsColor(tshark string) (bool, error) {
	exitCode, err := RunForExitCode(
		tshark,
		[]string{"-r", CacheFile("empty.pcap"), "-T", "psml", "-w", os.DevNull, "--color"},
		nil,
	)
	return exitCode == 0, err
}

// TSharkPath will return the full path of the tshark binary, if it's found in the path, otherwise an error
func TSharkPath() (string, *gowid.KeyValueError) {
	tsharkBin := ConfString("main.tshark", "")
	if tsharkBin != "" {
		confirmedTshark := false
		if _, err := os.Stat(tsharkBin); err == nil {
			confirmedTshark = true
		} else if IsCommandInPath(tsharkBin) {
			confirmedTshark = true
		}
		// This message is for a configured tshark binary that is invalid
		if !confirmedTshark {
			err := gowid.WithKVs(ConfigErr, map[string]interface{}{
				"msg": fmt.Sprintf("Could not run tshark binary '%s'. The tshark binary is required to run termshark.\n", tsharkBin) +
					fmt.Sprintf("Check your config file %s\n", ConfFile("toml")),
			})
			return "", &err
		}
	} else {
		tsharkBin = "tshark"
		if !IsCommandInPath(tsharkBin) {
			// This message is for an unconfigured tshark bin (via PATH) that is invalid
			errstr := fmt.Sprintf("Could not find tshark in your PATH. The tshark binary is required to run termshark.\n")
			if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
				errstr += fmt.Sprintf("Try installing with: pkg install root-repo && pkg install tshark")
			} else if IsCommandInPath("apt") {
				errstr += fmt.Sprintf("Try installing with: apt install tshark")
			} else if IsCommandInPath("apt-get") {
				errstr += fmt.Sprintf("Try installing with: apt-get install tshark")
			} else if IsCommandInPath("yum") {
				errstr += fmt.Sprintf("Try installing with: yum install wireshark")
			} else if IsCommandInPath("brew") {
				errstr += fmt.Sprintf("Try installing with: brew install wireshark")
			}
			errstr += "\n"
			err := gowid.WithKVs(ConfigErr, map[string]interface{}{
				"msg": errstr,
			})
			return "", &err
		}
	}
	// Here we know it's in PATH
	tsharkBin = DirOfPathCommandUnsafe(tsharkBin)
	return tsharkBin, nil
}

func RunForExitCode(prog string, args []string, env []string) (int, error) {
	var err error
	exitCode := -1 // default bad
	cmd := exec.Command(prog, args...)
	if env != nil {
		cmd.Env = env
	}
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

// A separate dir from CacheDir because I need to use inotify under some
// circumstances for a non-existent file, meaning I need to track a directory,
// and I don't want to be constantly triggered by log file updates.
func PcapDir() string {
	return path.Join(CacheDir(), "pcaps")
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
		def = []string{os.Args[0], "--tail"}
	}
	return ConfStringSlice("main.tail-command", def)
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
		gr, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gr.Close()
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
	if !errProcessAlreadyFinished(err) {
		return err
	} else {
		return nil
	}
}

func errProcessAlreadyFinished(err error) bool {
	if err == nil {
		return false
	}
	// Terrible hack - but the error isn't published
	return err.Error() == "os: process already finished"
}

func SafePid(p IProcess) int {
	if p == nil {
		return -1
	}
	return p.Pid()
}

func AddToRecentFiles(pcap string) {
	comps := ConfStrings("main.recent-files")
	if len(comps) == 0 || comps[0] != pcap {
		comps = RemoveFromStringSlice(pcap, comps)
		if len(comps) > 16 {
			comps = comps[0 : 16-1]
		}
		SetConf("main.recent-files", comps)
	}
}

func AddToRecentFilters(val string) {
	comps := ConfStrings("main.recent-filters")
	if (len(comps) == 0 || comps[0] != val) && strings.TrimSpace(val) != "" {
		comps = RemoveFromStringSlice(val, comps)
		if len(comps) > 64 {
			comps = comps[0 : 64-1]
		}
		SetConf("main.recent-filters", comps)
	}
}

func LoadOffsetFromConfig(name string) ([]resizable.Offset, error) {
	offsStr := ConfString("main."+name, "")
	if offsStr == "" {
		return nil, errors.WithStack(gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": name,
			"msg":  "No offsets found",
		}))
	}
	res := make([]resizable.Offset, 0)
	err := json.Unmarshal([]byte(offsStr), &res)
	if err != nil {
		return nil, errors.WithStack(gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": name,
			"msg":  "Could not unmarshal offsets",
		}))
	}
	return res, nil
}

func SaveOffsetToConfig(name string, offsets2 []resizable.Offset) {
	offsets := make([]resizable.Offset, 0)
	for _, off := range offsets2 {
		if off.Adjust != 0 {
			offsets = append(offsets, off)
		}
	}
	if len(offsets) == 0 {
		DeleteConf(name)
	} else {
		offs, err := json.Marshal(offsets)
		if err != nil {
			log.Fatal(err)
		}
		SetConf("main."+name, string(offs))
	}
	// Hack to make viper save if I only deleted from the map
	SetConf("main.lastupdate", time.Now().String())
}

//======================================================================

var cpuProfileRunning *abool.AtomicBool

func init() {
	cpuProfileRunning = abool.New()
}

// Down to the second for profiling, etc
func DateStringForFilename() string {
	return time.Now().Format("2006-01-02--15-04-05")
}

func ProfileCPUFor(secs int) bool {
	if !cpuProfileRunning.SetToIf(false, true) {
		log.Infof("CPU profile already running.")
		return false
	}
	file := filepath.Join(CacheDir(), fmt.Sprintf("cpu-%s.prof", DateStringForFilename()))
	log.Infof("Starting CPU profile for %d seconds in %s", secs, file)
	gwutil.StartProfilingCPU(file)
	go func() {
		time.Sleep(time.Duration(secs) * time.Second)
		log.Infof("Stopping CPU profile")
		gwutil.StopProfilingCPU()
		cpuProfileRunning.UnSet()
	}()

	return true
}

func ProfileHeap() {
	file := filepath.Join(CacheDir(), fmt.Sprintf("mem-%s.prof", DateStringForFilename()))
	log.Infof("Creating memory profile in %s", file)
	gwutil.ProfileHeap(file)
}

func LocalIPs() []string {
	res := make([]string, 0)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return res
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			res = append(res, ipnet.IP.String())
		}
	}
	return res
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
func Interfaces() (map[int][]string, error) {
	cmd := exec.Command(TSharkBin(), "-D")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return interfacesFrom(bytes.NewReader(out))
}

func interfacesFrom(reader io.Reader) (map[int][]string, error) {
	re := regexp.MustCompile(`^(?P<index>[0-9]+)\.\s+(?P<name1>[^\s]+)(\s*\((?P<name2>[^)]+)\))?`)

	res := make(map[int][]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		match := re.FindStringSubmatch(line)
		if len(match) < 2 {
			return nil, gowid.WithKVs(UnexpectedOutput, map[string]interface{}{"Output": line})
		}
		result := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && match[i] != "" {
				result[name] = match[i]
			}
		}

		i, err := strconv.ParseInt(result["index"], 10, 32)
		if err != nil {
			return nil, gowid.WithKVs(UnexpectedOutput, map[string]interface{}{"Output": line})
		}

		val := make([]string, 0)
		val = append(val, result["name1"])

		if name2, ok := result["name2"]; ok {
			val = append([]string{name2}, val...)
		}
		res[int(i)] = val
	}

	return res, nil
}

//======================================================================

func IsTerminal(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
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

type iWrappedError interface {
	Cause() error
}

func RootCause(err error) error {
	res := err
	for {
		if cerr, ok := res.(iWrappedError); ok {
			res = cerr.Cause()
		} else {
			break
		}
	}
	return res
}

//======================================================================

func RunningRemotely() bool {
	return os.Getenv("SSH_TTY") != ""
}

// ApplyArguments turns ["echo", "hello", "$2"] + ["big", "world"] into
// ["echo", "hello", "world"]
func ApplyArguments(cmd []string, args []string) ([]string, int) {
	total := 0
	re := regexp.MustCompile("^\\$([1-9][0-9]{0,4})$")
	res := make([]string, len(cmd))
	for i, c := range cmd {
		changed := false
		matches := re.FindStringSubmatch(c)
		if len(matches) > 1 {
			unum, _ := strconv.ParseUint(matches[1], 10, 32)
			num := int(unum)
			num -= 1 // 1 indexed
			if num < len(args) {
				res[i] = args[num]
				changed = true
				total += 1
			}
		}
		if !changed {
			res[i] = c
		}
	}
	return res, total
}

func BrowseUrl(url string) error {
	urlCmd := ConfStringSlice(
		"main.browse-command",
		system.OpenURL,
	)

	if len(urlCmd) == 0 {
		return errors.WithStack(gowid.WithKVs(BadCommand, map[string]interface{}{"message": "browse command is nil"}))
	}

	urlCmdPP, changed := ApplyArguments(urlCmd, []string{url})
	if changed == 0 {
		urlCmdPP = append(urlCmd, url)
	}

	cmd := exec.Command(urlCmdPP[0], urlCmdPP[1:]...)

	return cmd.Run()
}

//======================================================================

type ICommandOutput interface {
	ProcessOutput(output string) error
}

type ICommandError interface {
	ProcessCommandError(err error) error
}

type ICommandDone interface {
	ProcessCommandDone()
}

type ICommandKillError interface {
	ProcessKillError(err error) error
}

type ICommandTimeout interface {
	ProcessCommandTimeout() error
}

type ICommandWaitTicker interface {
	ProcessWaitTick() error
}

func CopyCommand(input io.Reader, cb interface{}) error {
	var err error

	copyCmd := ConfStringSlice(
		"main.copy-command",
		system.CopyToClipboard,
	)

	if len(copyCmd) == 0 {
		return errors.WithStack(gowid.WithKVs(BadCommand, map[string]interface{}{"message": "copy command is nil"}))
	}

	cmd := exec.Command(copyCmd[0], copyCmd[1:]...)
	cmd.Stdin = input
	outBuf := bytes.Buffer{}
	cmd.Stdout = &outBuf

	cmdTimeout := ConfInt("main.copy-command-timeout", 5)
	if err := cmd.Start(); err != nil {
		return errors.WithStack(gowid.WithKVs(BadCommand, map[string]interface{}{"err": err}))
	}

	TrackedGo(func() {

		defer func() {
			if po, ok := cb.(ICommandDone); ok {
				po.ProcessCommandDone()
			}
		}()

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		tick := time.NewTicker(time.Duration(200) * time.Millisecond)
		defer tick.Stop()
		tchan := time.After(time.Duration(cmdTimeout) * time.Second)

	Loop:
		for {
			select {
			case <-tick.C:
				if po, ok := cb.(ICommandWaitTicker); ok {
					err = po.ProcessWaitTick()
					if err != nil {
						break Loop
					}
				}

			case <-tchan:
				if err := cmd.Process.Kill(); err != nil {
					if po, ok := cb.(ICommandKillError); ok {
						err = po.ProcessKillError(err)
						if err != nil {
							break Loop
						}
					}
				} else {
					if po, ok := cb.(ICommandTimeout); ok {
						err = po.ProcessCommandTimeout()
						if err != nil {
							break Loop
						}
					}
				}
				break Loop

			case err := <-done:
				if err != nil {
					if po, ok := cb.(ICommandError); ok {
						po.ProcessCommandError(err)
					}
				} else {
					if po, ok := cb.(ICommandOutput); ok {
						outStr := outBuf.String()
						po.ProcessOutput(outStr)
					}
				}
				break Loop
			}
		}

	})

	return nil
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
