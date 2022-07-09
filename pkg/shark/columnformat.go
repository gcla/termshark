// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package shark

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/gcla/gowid/widgets/table"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/configs/profiles"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

//======================================================================

type PsmlField struct {
	Token      string
	Filter     string
	Occurrence int
}

func (p PsmlField) FullString() string {
	return fmt.Sprintf("%s:%s:%d:R", p.Token, p.Filter, p.Occurrence)
}

func (p PsmlField) String() string {
	if p.Filter == "" {
		return p.Token
	} else {
		return p.FullString()
	}
}

var InvalidCustomColumnError = fmt.Errorf("The custom column is invalid")

func (p *PsmlField) FromString(s string) error {
	fields := strings.Split(s, ":")
	if len(fields) == 1 {
		if fields[0] == "%Cus" {
			//logrus.Warnf("Found a custom column with no definition - ignoring")
			return InvalidCustomColumnError
		}
		*p = PsmlField{Token: fields[0]}
	} else if len(fields) != 4 {
		return InvalidCustomColumnError
		//logrus.Warnf("Found an unexpected custom column '%s' - ignoring", pieces[0])
		//continue
	} else {
		occ, err := strconv.ParseInt(fields[2], 10, 32)
		if err != nil {
			return InvalidCustomColumnError
			//logrus.Warnf("Found an unexpected occurrence in a custom column '%s' - ignoring", pieces[0])
			//continue
		}
		*p = PsmlField{
			Token:      fields[0],
			Filter:     fields[1],
			Occurrence: int(occ),
		}
		//p.Field.Token = fields[0]
		//p.Field.Filter = fields[1]
		//p.Field.Occurrence = int(occ)
	}
	return nil
}

type PsmlColumnSpec struct {
	Name   string
	Field  PsmlField
	Hidden bool
}

var DefaultPsmlColumnSpec = []PsmlColumnSpec{
	PsmlColumnSpec{Field: PsmlField{Token: "%m"}, Name: "No."},
	PsmlColumnSpec{Field: PsmlField{Token: "%t"}, Name: "Time"},
	PsmlColumnSpec{Field: PsmlField{Token: "%s"}, Name: "Source"},
	PsmlColumnSpec{Field: PsmlField{Token: "%d"}, Name: "Dest"},
	PsmlColumnSpec{Field: PsmlField{Token: "%p"}, Name: "Proto"},
	PsmlColumnSpec{Field: PsmlField{Token: "%L"}, Name: "Length"},
	PsmlColumnSpec{Field: PsmlField{Token: "%i"}, Name: "Info"},
}

type PsmlColumnInfo struct {
	Field      string
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
	"%q":      PsmlColumnInfo{Field: "%q", Short: "VLAN", Long: "802.1Q VLAN id", Comparator: table.IntCompare{}},                                /* 0) COL_8021Q_VLAN_ID */
	"%Yt":     PsmlColumnInfo{Field: "%Yt", Short: "Time", Long: "Absolute date, as YYYY-MM-DD, and time", Comparator: table.DateTimeCompare{}},  /* 1) COL_ABS_YMD_TIME */
	"%YDOYt":  PsmlColumnInfo{Field: "%YDOYt", Short: "Time", Long: "Absolute date, as YYYY/DOY, and time", Comparator: table.DateTimeCompare{}}, /* 2) COL_ABS_YDOY_TIME */
	"%At":     PsmlColumnInfo{Field: "%At", Short: "Time", Long: "Absolute time", Comparator: table.DateTimeCompare{}},                           /* 3) COL_ABS_TIME */
	"%V":      PsmlColumnInfo{Field: "%V", Short: "VSAN", Long: "Cisco VSAN"},                                                                    /* 4) COL_VSAN - !! DEPRECATED !!*/
	"%B":      PsmlColumnInfo{Field: "%B", Short: "Cuml Bytes", Long: "Cumulative Bytes", Comparator: table.IntCompare{}},                        /* 5) COL_CUMULATIVE_BYTES */
	"%Cus":    PsmlColumnInfo{Field: "%Cus", Short: "Custom", Long: "Custom"},                                                                    /* 6) COL_CUSTOM */
	"%y":      PsmlColumnInfo{Field: "%y", Short: "DCE/RPC", Long: "DCE/RPC call (cn_call_id / dg_seqnum)", Comparator: table.IntCompare{}},      /* 7) COL_DCE_CALL */
	"%Tt":     PsmlColumnInfo{Field: "%Tt", Short: "Time Delt", Long: "Delta time", Comparator: table.FloatCompare{}},                            /* 8) COL_DELTA_TIME */
	"%Gt":     PsmlColumnInfo{Field: "%Gt", Short: "Time Delt", Long: "Delta time displayed", Comparator: table.FloatCompare{}},                  /* 9) COL_DELTA_TIME_DIS */
	"%rd":     PsmlColumnInfo{Field: "%rd", Short: "Dest", Long: "Dest addr (resolved)"},                                                         /* 10) COL_RES_DST */
	"%ud":     PsmlColumnInfo{Field: "%ud", Short: "Dest", Long: "Dest addr (unresolved)", Comparator: termshark.IPCompare{}},                    /* 11) COL_UNRES_DST */
	"%rD":     PsmlColumnInfo{Field: "%rD", Short: "DPort", Long: "Dest port (resolved)"},                                                        /* 12) COL_RES_DST_PORT */
	"%uD":     PsmlColumnInfo{Field: "%uD", Short: "DPort", Long: "Dest port (unresolved)", Comparator: table.IntCompare{}},                      /* 13) COL_UNRES_DST_PORT */
	"%d":      PsmlColumnInfo{Field: "%d", Short: "Dest", Long: "Destination address"},                                                           /* 14) COL_DEF_DST */
	"%D":      PsmlColumnInfo{Field: "%D", Short: "DPort", Long: "Destination port", Comparator: table.IntCompare{}},                             /* 15) COL_DEF_DST_PORT */
	"%a":      PsmlColumnInfo{Field: "%a", Short: "Expert", Long: "Expert Info Severity"},                                                        /* 16) COL_EXPERT */
	"%I":      PsmlColumnInfo{Field: "%I", Short: "FW-1", Long: "FW-1 monitor if/direction"},                                                     /* 17) COL_IF_DIR */
	"%F":      PsmlColumnInfo{Field: "%F", Short: "Freq/Chan", Long: "Frequency/Channel", Comparator: table.IntCompare{}},                        /* 18) COL_FREQ_CHAN */
	"%hd":     PsmlColumnInfo{Field: "%hd", Short: "DMAC", Long: "Hardware dest addr"},                                                           /* 19) COL_DEF_DL_DST */
	"%hs":     PsmlColumnInfo{Field: "%hs", Short: "SMAC", Long: "Hardware src addr"},                                                            /* 20) COL_DEF_DL_SRC */
	"%rhd":    PsmlColumnInfo{Field: "%rhd", Short: "DMAC", Long: "Hw dest addr (resolved)"},                                                     /* 21) COL_RES_DL_DST */
	"%uhd":    PsmlColumnInfo{Field: "%uhd", Short: "DMAC", Long: "Hw dest addr (unresolved)"},                                                   /* 22) COL_UNRES_DL_DST */
	"%rhs":    PsmlColumnInfo{Field: "%rhs", Short: "SMAC", Long: "Hw src addr (resolved)"},                                                      /* 23) COL_RES_DL_SRC*/
	"%uhs":    PsmlColumnInfo{Field: "%uhs", Short: "SMAC", Long: "Hw src addr (unresolved)"},                                                    /* 24) COL_UNRES_DL_SRC */
	"%e":      PsmlColumnInfo{Field: "%e", Short: "RSSI", Long: "IEEE 802.11 RSSI", Comparator: table.FloatCompare{}},                            /* 25) COL_RSSI */
	"%x":      PsmlColumnInfo{Field: "%x", Short: "TX Rate", Long: "IEEE 802.11 TX rate", Comparator: table.FloatCompare{}},                      /* 26) COL_TX_RATE */
	"%f":      PsmlColumnInfo{Field: "%f", Short: "DSCP", Long: "IP DSCP Value"},                                                                 /* 27) COL_DSCP_VALUE */
	"%i":      PsmlColumnInfo{Field: "%i", Short: "Info", Long: "Information"},                                                                   /* 28) COL_INFO */
	"%rnd":    PsmlColumnInfo{Field: "%rnd", Short: "Dest", Long: "Net dest addr (resolved)"},                                                    /* 29) COL_RES_NET_DST */
	"%und":    PsmlColumnInfo{Field: "%und", Short: "Dest", Long: "Net dest addr (unresolved)", Comparator: termshark.IPCompare{}},               /* 30) COL_UNRES_NET_DST */
	"%rns":    PsmlColumnInfo{Field: "%rns", Short: "Source", Long: "Net src addr (resolved)"},                                                   /* 31) COL_RES_NET_SRC */
	"%uns":    PsmlColumnInfo{Field: "%uns", Short: "Source", Long: "Net src addr (unresolved)", Comparator: termshark.IPCompare{}},              /* 32) COL_UNRES_NET_SRC */
	"%nd":     PsmlColumnInfo{Field: "%nd", Short: "Dest", Long: "Network dest addr"},                                                            /* 33) COL_DEF_NET_DST */
	"%ns":     PsmlColumnInfo{Field: "%ns", Short: "Dest", Long: "Network src addr"},                                                             /* 34) COL_DEF_NET_SRC */
	"%m":      PsmlColumnInfo{Field: "%m", Short: "No.", Long: "Number", Comparator: table.IntCompare{}},                                         /* 35) COL_NUMBER */
	"%L":      PsmlColumnInfo{Field: "%L", Short: "Length", Long: "Packet length (bytes)", Comparator: table.IntCompare{}},                       /* 36) COL_PACKET_LENGTH */
	"%p":      PsmlColumnInfo{Field: "%p", Short: "Proto", Long: "Protocol"},                                                                     /* 37) COL_PROTOCOL */ // IGMPv3, NBNS, TLSv1.3
	"%Rt":     PsmlColumnInfo{Field: "%Rt", Short: "Time", Long: "Relative time", Comparator: table.FloatCompare{}},                              /* 38) COL_REL_TIME */ // 5.961798653
	"%s":      PsmlColumnInfo{Field: "%s", Short: "Source", Long: "Source address", Comparator: termshark.IPCompare{}},                           /* 39) COL_DEF_SRC */
	"%S":      PsmlColumnInfo{Field: "%S", Short: "SPort", Long: "Source port", Comparator: table.IntCompare{}},                                  /* 40) COL_DEF_SRC_PORT */
	"%rs":     PsmlColumnInfo{Field: "%rs", Short: "Source", Long: "Src addr (resolved)"},                                                        /* 41) COL_RES_SRC */
	"%us":     PsmlColumnInfo{Field: "%us", Short: "Source", Long: "Src addr (unresolved)", Comparator: termshark.IPCompare{}},                   /* 42) COL_UNRES_SRC */
	"%rS":     PsmlColumnInfo{Field: "%rS", Short: "SPort", Long: "Src port (resolved)"},                                                         /* 43) COL_RES_SRC_PORT */
	"%uS":     PsmlColumnInfo{Field: "%uS", Short: "SPort", Long: "Src port (unresolved)", Comparator: table.IntCompare{}},                       /* 44) COL_UNRES_SRC_PORT */
	"%E":      PsmlColumnInfo{Field: "%E", Short: "TEI", Long: "TEI", Comparator: table.IntCompare{}},                                            /* 45) COL_TEI */
	"%Yut":    PsmlColumnInfo{Field: "%Yut", Short: "Time", Long: "UTC date, as YYYY-MM-DD, and time", Comparator: table.DateTimeCompare{}},      /* 46) COL_UTC_YMD_TIME */
	"%YDOYut": PsmlColumnInfo{Field: "%YDOYut", Short: "Time", Long: "UTC date, as YYYY/DOY, and time", Comparator: table.DateTimeCompare{}},     /* 47) COL_UTC_YDOY_TIME */
	"%Aut":    PsmlColumnInfo{Field: "%Aut", Short: "Time", Long: "UTC time", Comparator: table.DateTimeCompare{}},                               /* 48) COL_UTC_TIME */
	"%t":      PsmlColumnInfo{Field: "%t", Short: "Time", Long: "Time (format as specified)", Comparator: table.DateTimeCompare{}},               /* 49) COL_CLS_TIME */ // 6916.185051
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
var ColumnsFormatError = fmt.Errorf("The supplied list of columns and names is invalid")

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
		if cached, ok := BuiltInColumnFormats[f.Field.Token]; ok {
			AllowedColumnFormats[f.Field.Token] = cached.WithLongName(f.Name)
		} else {
			// We don't have a short name from tshark... :(
			AllowedColumnFormats[f.Field.Token] = PsmlColumnInfo{Short: f.Name, Long: f.Name}
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
		if len(fields) == 2 && strings.HasPrefix(fields[0], "%") {
			w.fields = append(w.fields, PsmlColumnSpec{
				Field: PsmlField{Token: fields[0]},
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
		cachedPsmlColumnFormat = getPsmlColumnFormatWithoutLock("main.column-format")
	}

	return cachedPsmlColumnFormat
}

func GetPsmlColumnFormat() []PsmlColumnSpec {
	cachedPsmlColumnFormatMutex.Lock()
	defer cachedPsmlColumnFormatMutex.Unlock()

	cachedPsmlColumnFormat = getPsmlColumnFormatWithoutLock("main.column-format")

	return cachedPsmlColumnFormat
}

func GetPsmlColumnFormatFrom(colKey string) []PsmlColumnSpec {
	return getPsmlColumnFormatWithoutLock(colKey)
}

func getPsmlColumnFormatWithoutLock(colKey string) []PsmlColumnSpec {
	res := make([]PsmlColumnSpec, 0)
	widths := profiles.ConfStringSlice(colKey, []string{})
	if len(widths) == 0 || (len(widths)/3)*3 != len(widths) {
		logrus.Warnf("Unexpected %s structure - using defaults", colKey)
		res = DefaultPsmlColumnSpec
	} else {
		// Cross references with those column specs that we know about from having
		// queried tshark with tshark -G column-formats. Any that are not known
		// are discarded. If none are left, use our safe defaults
		pieces := [3]string{}

		for i := 0; i < len(widths); i += 3 {
			pieces[0] = widths[i]
			pieces[1] = widths[i+1]
			pieces[2] = widths[i+2]

			var spec PsmlColumnSpec

			err := spec.Field.FromString(pieces[0])
			if err != nil {
				logrus.Warnf(err.Error())
				continue
			}

			if _, ok := AllowedColumnFormats[spec.Field.Token]; !ok {
				logrus.Warnf("Do not understand PSML column format token '%s' - skipping its use", pieces[0])
				continue
			}

			if pieces[1] != "" {
				spec.Name = pieces[1]
			} else {
				// Already confirmed it's in map
				spec.Name = AllowedColumnFormats[pieces[0]].Short
			}

			visible, err := strconv.ParseBool(pieces[2])
			if err != nil {
				logrus.Warnf("Do not understand PSML column format hidden token '%s' - skipping its use", pieces[2])
				continue
			}
			spec.Hidden = !visible

			res = append(res, spec)
		}
		if len(res) == 0 {
			logrus.Warnf("No configured PSML column formats were understood. Using safe default")
			res = DefaultPsmlColumnSpec
		}

	}
	return res
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
