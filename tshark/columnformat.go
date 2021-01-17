// Copyright 2019-2021 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package tshark

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type PsmlColumnSpec struct {
	Field string
	Name  string
}

var defaultPsmlColumnSpec = []PsmlColumnSpec{
	PsmlColumnSpec{Field: "%m", Name: "No."},
	PsmlColumnSpec{Field: "%t", Name: "Time"},
	PsmlColumnSpec{Field: "%s", Name: "Source"},
	PsmlColumnSpec{Field: "%d", Name: "Dest"},
	PsmlColumnSpec{Field: "%p", Name: "Proto"},
	PsmlColumnSpec{Field: "%L", Name: "Length"},
	PsmlColumnSpec{Field: "%i", Name: "Info"},
}

type PsmlColumnInfo struct {
	Short      string
	Long       string
	Comparator table.ICompare
}

// AllowedColumnFormats is initialized when the cached columns file is read from disk
var AllowedColumnFormats map[string]PsmlColumnInfo

// BuiltInColumnFormats is the list we know of, from tshark as of the end of 2020. I'll keep this
// up to date over time. The canonical list is retrieved from tshark -G column-formats, then merged
// with this to add useful short names and comparators.
var BuiltInColumnFormats = map[string]PsmlColumnInfo{
	"%q":      PsmlColumnInfo{Short: "VLAN", Long: "802.1Q VLAN id", Comparator: table.IntCompare{}},                              /* 0) COL_8021Q_VLAN_ID */
	"%Yt":     PsmlColumnInfo{Short: "Time", Long: "Absolute date, as YYYY-MM-DD, and time", Comparator: table.DateTimeCompare{}}, /* 1) COL_ABS_YMD_TIME */
	"%YDOYt":  PsmlColumnInfo{Short: "Time", Long: "Absolute date, as YYYY/DOY, and time", Comparator: table.DateTimeCompare{}},   /* 2) COL_ABS_YDOY_TIME */
	"%At":     PsmlColumnInfo{Short: "Time", Long: "Absolute time", Comparator: table.DateTimeCompare{}},                          /* 3) COL_ABS_TIME */
	"%V":      PsmlColumnInfo{Short: "VSAN", Long: "Cisco VSAN"},                                                                  /* 4) COL_VSAN - !! DEPRECATED !!*/
	"%B":      PsmlColumnInfo{Short: "Cuml Bytes", Long: "Cumulative Bytes", Comparator: table.IntCompare{}},                      /* 5) COL_CUMULATIVE_BYTES */
	"%Cus":    PsmlColumnInfo{Short: "Custom", Long: "Custom"},                                                                    /* 6) COL_CUSTOM */
	"%y":      PsmlColumnInfo{Short: "DCE/RPC", Long: "DCE/RPC call (cn_call_id / dg_seqnum)", Comparator: table.IntCompare{}},    /* 7) COL_DCE_CALL */
	"%Tt":     PsmlColumnInfo{Short: "Time Delt", Long: "Delta time", Comparator: table.FloatCompare{}},                           /* 8) COL_DELTA_TIME */
	"%Gt":     PsmlColumnInfo{Short: "Time Delt", Long: "Delta time displayed", Comparator: table.FloatCompare{}},                 /* 9) COL_DELTA_TIME_DIS */
	"%rd":     PsmlColumnInfo{Short: "Dest", Long: "Dest addr (resolved)"},                                                        /* 10) COL_RES_DST */
	"%ud":     PsmlColumnInfo{Short: "Dest", Long: "Dest addr (unresolved)", Comparator: termshark.IPCompare{}},                   /* 11) COL_UNRES_DST */
	"%rD":     PsmlColumnInfo{Short: "DPort", Long: "Dest port (resolved)"},                                                       /* 12) COL_RES_DST_PORT */
	"%uD":     PsmlColumnInfo{Short: "DPort", Long: "Dest port (unresolved)", Comparator: table.IntCompare{}},                     /* 13) COL_UNRES_DST_PORT */
	"%d":      PsmlColumnInfo{Short: "Dest", Long: "Destination address"},                                                         /* 14) COL_DEF_DST */
	"%D":      PsmlColumnInfo{Short: "DPort", Long: "Destination port", Comparator: table.IntCompare{}},                           /* 15) COL_DEF_DST_PORT */
	"%a":      PsmlColumnInfo{Short: "Expert", Long: "Expert Info Severity"},                                                      /* 16) COL_EXPERT */
	"%I":      PsmlColumnInfo{Short: "FW-1", Long: "FW-1 monitor if/direction"},                                                   /* 17) COL_IF_DIR */
	"%F":      PsmlColumnInfo{Short: "Freq/Chan", Long: "Frequency/Channel", Comparator: table.IntCompare{}},                      /* 18) COL_FREQ_CHAN */
	"%hd":     PsmlColumnInfo{Short: "DMAC", Long: "Hardware dest addr"},                                                          /* 19) COL_DEF_DL_DST */
	"%hs":     PsmlColumnInfo{Short: "SMAC", Long: "Hardware src addr"},                                                           /* 20) COL_DEF_DL_SRC */
	"%rhd":    PsmlColumnInfo{Short: "DMAC", Long: "Hw dest addr (resolved)"},                                                     /* 21) COL_RES_DL_DST */
	"%uhd":    PsmlColumnInfo{Short: "DMAC", Long: "Hw dest addr (unresolved)"},                                                   /* 22) COL_UNRES_DL_DST */
	"%rhs":    PsmlColumnInfo{Short: "SMAC", Long: "Hw src addr (resolved)"},                                                      /* 23) COL_RES_DL_SRC*/
	"%uhs":    PsmlColumnInfo{Short: "SMAC", Long: "Hw src addr (unresolved)"},                                                    /* 24) COL_UNRES_DL_SRC */
	"%e":      PsmlColumnInfo{Short: "RSSI", Long: "IEEE 802.11 RSSI", Comparator: table.FloatCompare{}},                          /* 25) COL_RSSI */
	"%x":      PsmlColumnInfo{Short: "TX Rate", Long: "IEEE 802.11 TX rate", Comparator: table.FloatCompare{}},                    /* 26) COL_TX_RATE */
	"%f":      PsmlColumnInfo{Short: "DSCP", Long: "IP DSCP Value"},                                                               /* 27) COL_DSCP_VALUE */
	"%i":      PsmlColumnInfo{Short: "Info", Long: "Information"},                                                                 /* 28) COL_INFO */
	"%rnd":    PsmlColumnInfo{Short: "Dest", Long: "Net dest addr (resolved)"},                                                    /* 29) COL_RES_NET_DST */
	"%und":    PsmlColumnInfo{Short: "Dest", Long: "Net dest addr (unresolved)", Comparator: termshark.IPCompare{}},               /* 30) COL_UNRES_NET_DST */
	"%rns":    PsmlColumnInfo{Short: "Source", Long: "Net src addr (resolved)"},                                                   /* 31) COL_RES_NET_SRC */
	"%uns":    PsmlColumnInfo{Short: "Source", Long: "Net src addr (unresolved)", Comparator: termshark.IPCompare{}},              /* 32) COL_UNRES_NET_SRC */
	"%nd":     PsmlColumnInfo{Short: "Dest", Long: "Network dest addr"},                                                           /* 33) COL_DEF_NET_DST */
	"%ns":     PsmlColumnInfo{Short: "Dest", Long: "Network src addr"},                                                            /* 34) COL_DEF_NET_SRC */
	"%m":      PsmlColumnInfo{Short: "No.", Long: "Number", Comparator: table.IntCompare{}},                                       /* 35) COL_NUMBER */
	"%L":      PsmlColumnInfo{Short: "Length", Long: "Packet length (bytes)", Comparator: table.IntCompare{}},                     /* 36) COL_PACKET_LENGTH */
	"%p":      PsmlColumnInfo{Short: "Proto", Long: "Protocol"},                                                                   /* 37) COL_PROTOCOL */ // IGMPv3, NBNS, TLSv1.3
	"%Rt":     PsmlColumnInfo{Short: "Time", Long: "Relative time", Comparator: table.FloatCompare{}},                             /* 38) COL_REL_TIME */ // 5.961798653
	"%s":      PsmlColumnInfo{Short: "Source", Long: "Source address", Comparator: termshark.IPCompare{}},                         /* 39) COL_DEF_SRC */
	"%S":      PsmlColumnInfo{Short: "SPort", Long: "Source port", Comparator: table.IntCompare{}},                                /* 40) COL_DEF_SRC_PORT */
	"%rs":     PsmlColumnInfo{Short: "Source", Long: "Src addr (resolved)"},                                                       /* 41) COL_RES_SRC */
	"%us":     PsmlColumnInfo{Short: "Source", Long: "Src addr (unresolved)", Comparator: termshark.IPCompare{}},                  /* 42) COL_UNRES_SRC */
	"%rS":     PsmlColumnInfo{Short: "SPort", Long: "Src port (resolved)"},                                                        /* 43) COL_RES_SRC_PORT */
	"%uS":     PsmlColumnInfo{Short: "SPort", Long: "Src port (unresolved)", Comparator: table.IntCompare{}},                      /* 44) COL_UNRES_SRC_PORT */
	"%E":      PsmlColumnInfo{Short: "TEI", Long: "TEI", Comparator: table.IntCompare{}},                                          /* 45) COL_TEI */
	"%Yut":    PsmlColumnInfo{Short: "Time", Long: "UTC date, as YYYY-MM-DD, and time", Comparator: table.DateTimeCompare{}},      /* 46) COL_UTC_YMD_TIME */
	"%YDOYut": PsmlColumnInfo{Short: "Time", Long: "UTC date, as YYYY/DOY, and time", Comparator: table.DateTimeCompare{}},        /* 47) COL_UTC_YDOY_TIME */
	"%Aut":    PsmlColumnInfo{Short: "Time", Long: "UTC time", Comparator: table.DateTimeCompare{}},                               /* 48) COL_UTC_TIME */
	"%t":      PsmlColumnInfo{Short: "Time", Long: "Time (format as specified)", Comparator: table.DateTimeCompare{}},             /* 49) COL_CLS_TIME */ // 6916.185051
}

var cachedPsmlColumnFormat []PsmlColumnSpec
var cachedPsmlColumnFormatMutex sync.Mutex

// The fields field is serialized using gob.
type ColumnsFromTshark struct {
	once   sync.Once
	fields []PsmlColumnSpec
}

// Singleton
var validColumns *ColumnsFromTshark

var TsharkColumnsCacheOldError = fmt.Errorf("The cached tshark columns database is out of date")

func init() {
	// This will be computed from tshark -G column-formats. We then merge in some short
	// column names from all the fields we know. I'll have to keep that list up to date,
	// over time.
	AllowedColumnFormats = make(map[string]PsmlColumnInfo)
}

//======================================================================

func (p PsmlColumnInfo) WithLongName(name string) PsmlColumnInfo {
	p.Long = name
	return p
}

// InitValidColumns will run tshark, if necessary, to compute the columns that tshark understands. This
// is the set of columns the user is allowed to configure. This will block - if it's noticeable I'll make
// it async. This is called from termshark's main and makes specific assumptions i.e. that it can write
// to stdout and the user will see it.
func InitValidColumns() error {
	validColumns = &ColumnsFromTshark{}
	err := validColumns.InitFromCache()
	if err != nil {
		fmt.Printf("Termshark is initializing - please wait...\n")
		log.Infof("Did not read cached tshark column formats (%v) - regenerating...", err)
		// This will block for a second
		err = validColumns.InitNoCache()
		if err != nil {
			log.Warnf("Did not generate tshark column formats (%v)", err)
		} else {
			err = termshark.WriteGob(termshark.CacheFile("tsharkcolumnsv2.gob.gz"), validColumns.fields)
			if err != nil {
				log.Warnf("Could not serialize tshark column formats (%v)", err)
			}
		}
	}
	for _, f := range validColumns.fields {
		// Use short names that we understand
		if cached, ok := BuiltInColumnFormats[f.Field]; ok {
			AllowedColumnFormats[f.Field] = cached.WithLongName(f.Name)
		} else {
			// We don't have a short name from tshark... :(
			AllowedColumnFormats[f.Field] = PsmlColumnInfo{Short: f.Name, Long: f.Name}
		}
	}
	return err
}

func (w *ColumnsFromTshark) InitFromCache() error {
	newer, err := termshark.FileNewerThan(termshark.CacheFile("tsharkcolumnsv2.gob.gz"), termshark.DirOfPathCommandUnsafe(termshark.TSharkBin()))
	if err != nil {
		return err
	}

	if !newer {
		return TsharkColumnsCacheOldError
	}

	f := []PsmlColumnSpec{}
	err = termshark.ReadGob(termshark.CacheFile("tsharkcolumnsv2.gob.gz"), &f)
	if err != nil {
		return err
	}

	w.fields = f
	log.Infof("Read cached tshark column formats.")
	return nil
}

func (w *ColumnsFromTshark) InitNoCache() error {
	re := regexp.MustCompile("\\s+")

	cmd := exec.Command(termshark.TSharkBin(), []string{"-G", "column-formats"}...)

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	cmd.Start()

	w.fields = make([]PsmlColumnSpec, 0, 128)

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		fields := re.Split(scanner.Text(), 2)
		if len(fields) == 2 {
			w.fields = append(w.fields, PsmlColumnSpec{
				Field: fields[0],
				Name:  fields[1],
			})
		}
	}

	cmd.Wait()

	return nil
}

//======================================================================

func GetPsmlColumnFormatCached() []PsmlColumnSpec {
	cachedPsmlColumnFormatMutex.Lock()
	defer cachedPsmlColumnFormatMutex.Unlock()

	if cachedPsmlColumnFormat == nil {
		cachedPsmlColumnFormat = getPsmlColumnFormatWithoutLock()
	}

	return cachedPsmlColumnFormat
}

func GetPsmlColumnFormat() []PsmlColumnSpec {
	cachedPsmlColumnFormatMutex.Lock()
	defer cachedPsmlColumnFormatMutex.Unlock()

	cachedPsmlColumnFormat = getPsmlColumnFormatWithoutLock()

	return cachedPsmlColumnFormat
}

func getPsmlColumnFormatWithoutLock() []PsmlColumnSpec {
	res := make([]PsmlColumnSpec, 0)
	widths := termshark.ConfStringSlice("main.column-format", []string{})
	if len(widths) == 0 {
		res = defaultPsmlColumnSpec
	} else {
		// Cross references with those column specs that we know about from having
		// queried tshark with tshark -G column-formats. Any that are not known
		// are discarded. If none are left, use our safe defaults
		for _, w := range widths {
			var p PsmlColumnSpec
			pieces := strings.Split(w, " ")

			if _, ok := AllowedColumnFormats[pieces[0]]; !ok {
				logrus.Warnf("Do not understand PSML column format token '%s' - skipping its use", pieces[0])
				continue
			}
			p.Field = pieces[0]
			if len(pieces) >= 2 {
				p.Name = strings.Join(pieces[1:], " ")
			} else {
				// Already confirmed it's in map
				p.Name = AllowedColumnFormats[pieces[0]].Short
			}
			res = append(res, p)
		}
		if len(res) == 0 {
			logrus.Warnf("No configured PSML column formats were understood. Using safe default")
			res = defaultPsmlColumnSpec
		}
	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
