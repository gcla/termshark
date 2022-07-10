// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
	"unicode"

	"github.com/adam-hanna/arrayOperations"
	"github.com/blang/semver"
	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwutil"
	"github.com/gcla/gowid/vim"
	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/gcla/termshark/v2/pkg/system"
	"github.com/gcla/termshark/v2/widgets/resizable"
	"github.com/gdamore/tcell/v2"
	"github.com/gdamore/tcell/v2/terminfo"
	"github.com/gdamore/tcell/v2/terminfo/dynamic"
	"github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
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
	UserGuideURL         string = "https://termshark.io/userguide"
	FAQURL               string = "https://termshark.io/faq"
	BugURL               string = "https://github.com/gcla/termshark/issues/new?assignees=&labels=&template=bug_report.md&title="
	FeatureURL           string = "https://github.com/gcla/termshark/issues/new?assignees=&labels=&template=feature_request.md&title="
	OriginalEnv          []string
	ShouldSwitchTerminal bool
	ShouldSwitchBack     bool
	unitsRe              *regexp.Regexp = regexp.MustCompile(`^([0-9,]+)\s*(bytes|kB|MB)?`)
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

func ReverseStringSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
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
		[]string{"-r", CacheFile("empty.pcap"), "-T", "psml", "--color"},
		nil,
	)
	return exitCode == 0, err
}

// TSharkPath will return the full path of the tshark binary, if it's found in the path, otherwise an error
func TSharkPath() (string, *gowid.KeyValueError) {
	tsharkBin := profiles.ConfString("main.tshark", "")
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
	return RunForStderr(prog, args, env, ioutil.Discard)
}

func RunForStderr(prog string, args []string, env []string, stderr io.Writer) (int, error) {
	var err error
	exitCode := -1 // default bad
	cmd := exec.Command(prog, args...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = ioutil.Discard
	cmd.Stderr = stderr
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
	var res string
	// If use-tshark-temp-for-cache is set, use that
	if profiles.ConfBool("main.use-tshark-temp-for-pcap-cache", false) {
		tmp, err := TsharkSetting("Temp")
		if err == nil {
			res = tmp
		}
	}
	// Otherwise try the user's preference
	if res == "" {
		res = profiles.ConfString("main.pcap-cache-dir", "")
	}
	if res == "" {
		res = DefaultPcapDir()
	}
	return res
}

// DefaultPcapDir returns ~/.cache/pcaps by default. Termshark will check a
// couple of user settings first before using this.
func DefaultPcapDir() string {
	return path.Join(CacheDir(), "pcaps")
}

func TSharkBin() string {
	return profiles.ConfString("main.tshark", "tshark")
}

func DumpcapBin() string {
	return profiles.ConfString("main.dumpcap", "dumpcap")
}

func CapinfosBin() string {
	return profiles.ConfString("main.capinfos", "capinfos")
}

// CaptureBin is the binary the user intends to use to capture
// packets i.e. with the -i switch. This might be distinct from
// DumpcapBin because dumpcap can't capture on extcap interfaces
// like randpkt, but while tshark can, it can drop packets more
// readily than dumpcap. This value is interpreted as the name
// of a binary, resolved against PATH. Note that the default is
// termshark - this invokes termshark in a special mode where it
// first tries DumpcapBin, then if that fails, TSharkBin - for
// the best of both worlds. To detect this, termshark will run
// CaptureBin with TERMSHARK_CAPTURE_MODE=1 in the environment,
// so when termshark itself is invoked with this in the environment,
// it switches to capture mode.
func CaptureBin() string {
	if runtime.GOOS == "windows" {
		return profiles.ConfString("main.capture-command", DumpcapBin())
	} else {
		return profiles.ConfString("main.capture-command", os.Args[0])
	}
}

// PrivilegedBin returns a capture binary that may require setcap
// privileges on Linux. This is a simple UI to cover the fact that
// termshark's default capture method is to run dumpcap and tshark
// as a fallback. I don't want to tell the user the capture binary
// is termshark - that'd be confusing. We know that on Linux, termshark
// will run dumpcap first, then fall back to tshark if needed. Only
// dumpcap should need access to live interfaces; tshark is needed
// for extcap interfaces only. This is used to provide advice to
// the user if packet capture fails.
func PrivilegedBin() string {
	cap := CaptureBin()
	if cap == "termshark" {
		return DumpcapBin()
	} else {
		return cap
	}
}

func TailCommand() []string {
	def := []string{"tail", "-f", "-c", "+0"}
	if runtime.GOOS == "windows" {
		def = []string{os.Args[0], "--tail"}
	}
	return profiles.ConfStringSlice("main.tail-command", def)
}

func KeyPressIsPrintable(key gowid.IKey) bool {
	return unicode.IsPrint(key.Rune()) && key.Modifiers() & ^tcell.ModShift == 0
}

type KeyMapping struct {
	From vim.KeyPress
	To   vim.KeySequence
}

func AddKeyMapping(km KeyMapping) {
	mappings := LoadKeyMappings()
	newMappings := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		if mapping.From != km.From {
			newMappings = append(newMappings, mapping)
		}
	}
	newMappings = append(newMappings, km)
	SaveKeyMappings(newMappings)
}

func RemoveKeyMapping(kp vim.KeyPress) {
	mappings := LoadKeyMappings()
	newMappings := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		if mapping.From != kp {
			newMappings = append(newMappings, mapping)
		}
	}
	SaveKeyMappings(newMappings)
}

func LoadKeyMappings() []KeyMapping {
	mappings := profiles.ConfStringSlice("main.key-mappings", []string{})
	res := make([]KeyMapping, 0)
	for _, mapping := range mappings {
		pair := strings.Split(mapping, " ")
		if len(pair) != 2 {
			log.Warnf("Could not parse vim key mapping (missing separator?): %s", mapping)
			continue
		}
		from := vim.VimStringToKeys(pair[0])
		if len(from) != 1 {
			log.Warnf("Could not parse 'source' vim keypress: %s", pair[0])
			continue
		}
		to := vim.VimStringToKeys(pair[1])
		if len(to) < 1 {
			log.Warnf("Could not parse 'target' vim keypresses: %s", pair[1])
			continue
		}
		res = append(res, KeyMapping{From: from[0], To: to})
	}
	return res
}

func SaveKeyMappings(mappings []KeyMapping) {
	ser := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		ser = append(ser, fmt.Sprintf("%v %v", mapping.From, vim.KeySequence(mapping.To)))
	}
	profiles.SetConf("main.key-mappings", ser)
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
	if errProcessAlreadyFinished(err) {
		return nil
	} else {
		return err
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

func SetConvTypes(convs []string) {
	profiles.SetConf("main.conv-types", convs)
}

func ConvTypes() []string {
	defs := []string{"eth", "ip", "ipv6", "tcp", "udp"}
	ctypes := profiles.ConfStrings("main.conv-types")
	if len(ctypes) > 0 {
		z, ok := arrayOperations.Intersect(defs, ctypes)
		if ok {
			res, ok := z.Interface().([]string)
			if ok {
				return res
			}
		}
	}
	return defs
}

func AddToRecentFiles(pcap string) {
	comps := profiles.ConfStrings("main.recent-files")
	if len(comps) == 0 || comps[0] != pcap {
		comps = RemoveFromStringSlice(pcap, comps)
		if len(comps) > 16 {
			comps = comps[0 : 16-1]
		}
		profiles.SetConf("main.recent-files", comps)
	}
}

func AddToRecentFilters(val string) {
	addToRecent("main.recent-filters", val)
}

func addToRecent(field string, val string) {
	comps := profiles.ConfStrings(field)
	if (len(comps) == 0 || comps[0] != val) && strings.TrimSpace(val) != "" {
		comps = RemoveFromStringSlice(val, comps)
		if len(comps) > 64 {
			comps = comps[0 : 64-1]
		}
		profiles.SetConf(field, comps)
	}
}

func LoadOffsetFromConfig(name string) ([]resizable.Offset, error) {
	offsStr := profiles.ConfString("main."+name, "")
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
		profiles.DeleteConf("main." + name)
	} else {
		offs, err := json.Marshal(offsets)
		if err != nil {
			log.Fatal(err)
		}
		profiles.SetConf("main."+name, string(offs))
	}
	// Hack to make viper save if I only deleted from the map
	profiles.SetConf("main.lastupdate", time.Now().String())
}

//======================================================================

func ErrLogger(key string, val string) *io.PipeWriter {
	l := log.StandardLogger()
	return log.NewEntry(l).WithField(key, val).WriterLevel(log.ErrorLevel)
}

// KeyValueErrorString returns a string representation of
// a gowid KeyValueError intended to be suitable for displaying in
// a termshark error dialog.
func KeyValueErrorString(err gowid.KeyValueError) string {
	res := fmt.Sprintf("%v\n\n", err.Cause())
	kvs := make([]string, 0, len(err.KeyVals))
	ks := make([]string, 0, len(err.KeyVals))
	for k := range err.KeyVals {
		ks = append(ks, k)
	}
	sort.Sort(sort.StringSlice(ks))
	for _, k := range ks {
		kvs = append(kvs, fmt.Sprintf("%v: %v", k, err.KeyVals[k]))
	}
	res = res + strings.Join(kvs, "\n\n")
	return res
}

//======================================================================

// Need to publish fields for template use
type JumpPos struct {
	Summary string `json:"summary"`
	Pos     int    `json:"position"`
}

type GlobalJumpPos struct {
	JumpPos
	Filename string `json:"filename"`
}

// For ease of use in the template
func (g GlobalJumpPos) Base() string {
	return filepath.Base(g.Filename)
}

type globalJumpPosMapping struct {
	Key           rune `json:"key"`
	GlobalJumpPos      // embedding without a field name makes the json more concise
}

func LoadGlobalMarks(m map[rune]GlobalJumpPos) error {
	marksStr := profiles.ConfString("main.marks", "")
	if marksStr == "" {
		return nil
	}

	mappings := make([]globalJumpPosMapping, 0)
	err := json.Unmarshal([]byte(marksStr), &mappings)
	if err != nil {
		return errors.WithStack(gowid.WithKVs(ConfigErr, map[string]interface{}{
			"name": "marks",
			"msg":  "Could not unmarshal marks",
		}))
	}

	for _, mapping := range mappings {
		m[mapping.Key] = mapping.GlobalJumpPos
	}

	return nil
}

func SaveGlobalMarks(m map[rune]GlobalJumpPos) {
	marks := make([]globalJumpPosMapping, 0)
	for k, v := range m {
		marks = append(marks, globalJumpPosMapping{Key: k, GlobalJumpPos: v})
	}
	if len(marks) == 0 {
		profiles.DeleteConf("main.marks")
	} else {
		marksJ, err := json.Marshal(marks)
		if err != nil {
			log.Fatal(err)
		}
		profiles.SetConf("main.marks", string(marksJ))
	}
	// Hack to make viper save if I only deleted from the map
	profiles.SetConf("main.lastupdate", time.Now().String())
}

//======================================================================

// IPCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing IP addresses.
type IPCompare struct{}

func (s IPCompare) Less(i, j string) bool {
	x := net.ParseIP(i)
	y := net.ParseIP(j)
	if x != nil && y != nil {
		if len(x) != len(y) {
			return len(x) < len(y)
		} else {
			for i := 0; i < len(x); i++ {
				switch {
				case x[i] < y[i]:
					return true
				case y[i] < x[i]:
					return false
				}
			}
			return false
		}
	} else if x != nil {
		return true
	} else if y != nil {
		return false
	} else {
		return i < j
	}
}

var _ table.ICompare = IPCompare{}

//======================================================================

// MacCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing MAC addresses.
type MACCompare struct{}

func (s MACCompare) Less(i, j string) bool {
	x, errx := net.ParseMAC(i)
	y, erry := net.ParseMAC(j)
	if errx == nil && erry == nil {
		for i := 0; i < len(x); i++ {
			switch {
			case x[i] < y[i]:
				return true
			case y[i] < x[i]:
				return false
			}
		}
		return false
	} else if errx == nil {
		return true
	} else if erry == nil {
		return false
	} else {
		return i < j
	}
}

var _ table.ICompare = MACCompare{}

//======================================================================

// ConvPktsCompare is a unit type that satisfies ICompare, and can be used
// for numerically comparing values emitted by the tshark -z conv,... e.g.
// "2,456 kB"
type ConvPktsCompare struct{}

func (s ConvPktsCompare) Less(i, j string) bool {

	mi := unitsRe.FindStringSubmatch(i)
	if len(mi) <= 2 {
		return false
	}
	mx, err := strconv.ParseUint(strings.Replace(mi[1], ",", "", -1), 10, 64)
	if err != nil {
		return false
	}
	if mi[2] == "kB" {
		mx *= 1024
	} else if mi[2] == "MB" {
		mx *= (1024 * 1024)
	}
	mj := unitsRe.FindStringSubmatch(j)
	if len(mj) <= 2 {
		return false
	}
	my, err := strconv.ParseUint(strings.Replace(mj[1], ",", "", -1), 10, 64)
	if err != nil {
		return false
	}
	if mj[2] == "kB" {
		my *= 1024
	} else if mj[2] == "MB" {
		my *= (1024 * 1024)
	}

	return mx < my
}

var _ table.ICompare = ConvPktsCompare{}

//======================================================================

func PrunePcapCache() error {
	// This is a new option. Best to err on the side of caution and, if not, present
	// assume the cache can grow indefinitely - in case users are now relying on this
	// to keep old pcaps around. I don't want to delete any files without the user's
	// explicit permission.
	var diskCacheSize int64 = int64(profiles.ConfInt("main.disk-cache-size-mb", -1))

	if diskCacheSize == -1 {
		log.Infof("No pcap disk cache size set. Skipping cache pruning.")
		return nil
	}

	// Let user use MB as the most sensible unit of disk size. Convert to
	// bytes for comparing to file sizes.
	diskCacheSize = diskCacheSize * 1024 * 1024

	log.Infof("Pruning termshark's pcap disk cache at %s...", PcapDir())

	var totalSize int64
	var fileInfos []os.FileInfo
	err := filepath.Walk(PcapDir(),
		func(path string, info os.FileInfo, err error) error {
			if err == nil {
				totalSize += info.Size()
				fileInfos = append(fileInfos, info)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].ModTime().Before(fileInfos[j].ModTime())
	})

	filesRemoved := 0
	curCacheSize := totalSize
	for len(fileInfos) > 0 && curCacheSize > diskCacheSize {
		err = os.Remove(filepath.Join(PcapDir(), fileInfos[0].Name()))
		if err != nil {
			log.Warnf("Could not remove pcap cache file %s while pruning - %v", fileInfos[0].Name(), err)
		} else {
			curCacheSize = curCacheSize - fileInfos[0].Size()
			filesRemoved++
		}
		fileInfos = fileInfos[1:]
	}

	if filesRemoved > 0 {
		log.Infof("Pruning complete. Removed %d old pcaps. Cache size is now %d MB",
			filesRemoved, curCacheSize/(1024*1024))
	} else {
		log.Infof("Pruning complete. No old pcaps removed. Cache size is %d MB",
			curCacheSize/(1024*1024))
	}

	return nil
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

// Use tshark's output, because the indices can then be used to select
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

var foldersRE = regexp.MustCompile(`:\s*`)

// $ env TMPDIR=/foo tshark -G folders Temp
// Temp:                   /foo
// Personal configuration: /home/gcla/.config/wireshark
// Global configuration:   /usr/share/wireshark
//
func TsharkSetting(field string) (string, error) {
	res, err := TsharkSettings(field)
	if err != nil {
		return "", err
	}

	val, ok := res[field]
	if !ok {
		return "", fmt.Errorf("Field %s not found in output of tshark -G folders", field)
	}

	return val, nil
}

func TsharkSettings(fields ...string) (map[string]string, error) {
	out, err := exec.Command(TSharkBin(), []string{"-G", "folders"}...).Output()
	if err != nil {
		return nil, err
	}

	res := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		pieces := foldersRE.Split(line, 2)
		for _, field := range fields {
			if len(pieces) == 2 && pieces[0] == field {
				res[field] = pieces[1]
			}
		}
	}

	return res, nil
}

//======================================================================

func WiresharkProfileNames() []string {
	res := make([]string, 0, 8)
	folders, _ := TsharkSettings("Personal configuration", "Global configuration")
	for _, folder := range folders {
		profFolder := filepath.Join(folder, "profiles")

		files, err := ioutil.ReadDir(profFolder)
		if err != nil {
			log.Warnf("Could not read wireshark config folder %s: %v", profFolder, err)
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				res = append(res, file.Name())
			}
		}
	}
	return res
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
	urlCmd := profiles.ConfStringSlice(
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

type KeyState struct {
	NumberPrefix    int
	PartialgCmd     bool
	PartialZCmd     bool
	PartialCtrlWCmd bool
	PartialmCmd     bool
	PartialQuoteCmd bool
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

	copyCmd := profiles.ConfStringSlice(
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

	cmdTimeout := profiles.ConfInt("main.copy-command-timeout", 5)
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

// Returns true if error, too
func FileSizeDifferentTo(filename string, cur int64) (int64, bool) {
	var newSize int64
	diff := true
	fi, err := os.Stat(filename)
	if err == nil {
		newSize = fi.Size()
		if cur == newSize {
			diff = false
		}
	}
	return newSize, diff
}

func Does256ColorTermExist() error {
	return ValidateTerm(fmt.Sprintf("%s-256color", os.Getenv("TERM")))
}

func ValidateTerm(term string) error {
	var err error
	_, err = terminfo.LookupTerminfo(term)
	if err != nil {
		_, _, err = dynamic.LoadTerminfo(term)
	}
	return err
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
