// Copyright 2019-2021 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bufio"
	"encoding/gob"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

//======================================================================

type FieldType uint

//
// from epan/ftypes/ftypes.h
//
// enum ftenum {
const (
	FT_NONE              = iota /* used for text labels with no value */
	FT_PROTOCOL          = iota
	FT_BOOLEAN           = iota /* TRUE and FALSE come from <glib.h> */
	FT_CHAR              = iota /* 1-octet character as 0-255 */
	FT_UINT8             = iota
	FT_UINT16            = iota
	FT_UINT24            = iota /* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
	FT_UINT32            = iota
	FT_UINT40            = iota /* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
	FT_UINT48            = iota /* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
	FT_UINT56            = iota /* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
	FT_UINT64            = iota
	FT_INT8              = iota
	FT_INT16             = iota
	FT_INT24             = iota /* same as for UINT24 */
	FT_INT32             = iota
	FT_INT40             = iota /* same as for UINT40 */
	FT_INT48             = iota /* same as for UINT48 */
	FT_INT56             = iota /* same as for UINT56 */
	FT_INT64             = iota
	FT_IEEE_11073_SFLOAT = iota
	FT_IEEE_11073_FLOAT  = iota
	FT_FLOAT             = iota
	FT_DOUBLE            = iota
	FT_ABSOLUTE_TIME     = iota
	FT_RELATIVE_TIME     = iota
	FT_STRING            = iota
	FT_STRINGZ           = iota /* for use with proto_tree_add_item() */
	FT_UINT_STRING       = iota /* for use with proto_tree_add_item() */
	FT_ETHER             = iota
	FT_BYTES             = iota
	FT_UINT_BYTES        = iota
	FT_IPv4              = iota
	FT_IPv6              = iota
	FT_IPXNET            = iota
	FT_FRAMENUM          = iota /* a UINT32, but if selected lets you go to frame with that number */
	FT_PCRE              = iota /* a compiled Perl-Compatible Regular Expression object */
	FT_GUID              = iota /* GUID, UUID */
	FT_OID               = iota /* OBJECT IDENTIFIER */
	FT_EUI64             = iota
	FT_AX25              = iota
	FT_VINES             = iota
	FT_REL_OID           = iota /* RELATIVE-OID */
	FT_SYSTEM_ID         = iota
	FT_STRINGZPAD        = iota /* for use with proto_tree_add_item() */
	FT_FCWWN             = iota
	FT_NUM_TYPES         = iota /* last item number plus one */
)

var FieldTypeMap = map[string]FieldType{
	"FT_NONE":              FT_NONE,
	"FT_PROTOCOL":          FT_PROTOCOL,
	"FT_BOOLEAN":           FT_BOOLEAN,
	"FT_CHAR":              FT_CHAR,
	"FT_UINT8":             FT_UINT8,
	"FT_UINT16":            FT_UINT16,
	"FT_UINT24":            FT_UINT24,
	"FT_UINT32":            FT_UINT32,
	"FT_UINT40":            FT_UINT40,
	"FT_UINT48":            FT_UINT48,
	"FT_UINT56":            FT_UINT56,
	"FT_UINT64":            FT_UINT64,
	"FT_INT8":              FT_INT8,
	"FT_INT16":             FT_INT16,
	"FT_INT24":             FT_INT24,
	"FT_INT32":             FT_INT32,
	"FT_INT40":             FT_INT40,
	"FT_INT48":             FT_INT48,
	"FT_INT56":             FT_INT56,
	"FT_INT64":             FT_INT64,
	"FT_IEEE_11073_SFLOAT": FT_IEEE_11073_SFLOAT,
	"FT_IEEE_11073_FLOAT":  FT_IEEE_11073_FLOAT,
	"FT_FLOAT":             FT_FLOAT,
	"FT_DOUBLE":            FT_DOUBLE,
	"FT_ABSOLUTE_TIME":     FT_ABSOLUTE_TIME,
	"FT_RELATIVE_TIME":     FT_RELATIVE_TIME,
	"FT_STRING":            FT_STRING,
	"FT_STRINGZ":           FT_STRINGZ,
	"FT_UINT_STRING":       FT_UINT_STRING,
	"FT_ETHER":             FT_ETHER,
	"FT_BYTES":             FT_BYTES,
	"FT_UINT_BYTES":        FT_UINT_BYTES,
	"FT_IPv4":              FT_IPv4,
	"FT_IPv6":              FT_IPv6,
	"FT_IPXNET":            FT_IPXNET,
	"FT_FRAMENUM":          FT_FRAMENUM,
	"FT_PCRE":              FT_PCRE,
	"FT_GUID":              FT_GUID,
	"FT_OID":               FT_OID,
	"FT_EUI64":             FT_EUI64,
	"FT_AX25":              FT_AX25,
	"FT_VINES":             FT_VINES,
	"FT_REL_OID":           FT_REL_OID,
	"FT_SYSTEM_ID":         FT_SYSTEM_ID,
	"FT_STRINGZPAD":        FT_STRINGZPAD,
	"FT_FCWWN":             FT_FCWWN,
	"FT_NUM_TYPES":         FT_NUM_TYPES,
}

func ParseFieldType(s string) (res FieldType, ok bool) {
	res, ok = FieldTypeMap[s]
	return
}

type Protocol string

type Field struct {
	Name string
	Type FieldType
}

type FieldsAndProtos struct {
	Fields    interface{} // protocol or field or map[string]interface{}
	Protocols map[string]struct{}
}

func init() {
	gob.Register(make(map[string]interface{}))
	gob.Register(Protocol(""))
	gob.Register(Field{})
}

type TSharkFields struct {
	once sync.Once
	ser  *FieldsAndProtos
}

type IPrefixCompleterCallback interface {
	Call([]string)
}

type IPrefixCompleter interface {
	Completions(prefix string, cb IPrefixCompleterCallback)
}

func NewFields() *TSharkFields {
	return &TSharkFields{}
}

func DeleteCachedFields() error {
	return os.Remove(CacheFile("tsharkfieldsv3.gob.gz"))
}

// Can be run asynchronously.
// This ought to use interfaces to make it testable.
func (w *TSharkFields) Init() error {
	newer, err := FileNewerThan(CacheFile("tsharkfieldsv3.gob.gz"), DirOfPathCommandUnsafe(TSharkBin()))
	if err == nil && newer {
		f := &FieldsAndProtos{
			Fields:    make(map[string]interface{}),
			Protocols: make(map[string]struct{}),
		}

		err = ReadGob(CacheFile("tsharkfieldsv3.gob.gz"), f)
		if err == nil {
			w.ser = f
			log.Infof("Read cached tshark fields.")
			return nil
		} else {
			log.Infof("Could not read cached tshark fields (%v) - regenerating...", err)
		}
	}

	err = w.InitNoCache()
	if err != nil {
		return err
	}

	err = WriteGob(CacheFile("tsharkfieldsv3.gob.gz"), w.ser)
	if err != nil {
		return err
	}

	return nil
}

func (w *TSharkFields) InitNoCache() error {
	cmd := exec.Command(TSharkBin(), []string{"-G", "fields"}...)

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	cmd.Start()

	fieldsMap := make(map[string]interface{})
	protMap := make(map[string]struct{})

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "F") { // Wireshark field
			fields := strings.Split(line, "\t")
			protos := strings.SplitN(fields[2], ".", 2)
			if len(protos) > 1 {
				cur := fieldsMap
				for i := 0; i < len(protos)-1; i++ {
					if val, ok := cur[protos[i]]; ok {
						cur = val.(map[string]interface{})
					} else {
						next := make(map[string]interface{})
						cur[protos[i]] = next
						cur = next
					}
				}
				// Get none value if it's not found - so use that
				ty, _ := ParseFieldType(fields[3])
				cur[protos[len(protos)-1]] = Field{
					Name: fields[2],
					Type: ty,
				}
			}
		} else if strings.HasPrefix(line, "P") { // Wireshark protocol
			fields := strings.Split(line, "\t")
			protMap[fields[2]] = struct{}{}
		}
	}

	cmd.Wait()

	w.ser = &FieldsAndProtos{
		Fields:    fieldsMap,
		Protocols: protMap,
	}

	return nil
}

func dedup(s []string) []string {
	if len(s) == 0 {
		return s
	}
	i := 0
	for j := 1; j < len(s); j++ {
		if s[i] == s[j] {
			continue
		}
		i++
		s[i] = s[j]
	}
	return s[0 : i+1]
}

func (t *TSharkFields) LookupField(name string) (bool, Field) {
	fields := strings.Split(name, ".")

	cur := t.ser.Fields.(map[string]interface{})
	for i := 0; i < len(fields); i++ {
		if val, ok := cur[fields[i]]; ok {
			if i == len(fields)-1 {
				switch val := val.(type) {
				// means there's another level of indirection, so our input is too long
				case Field:
					return true, val
				default:
					return false, Field{}
				}
			} else {
				switch val := val.(type) {
				case map[string]interface{}:
					cur = val
				default:
					return false, Field{}
				}
			}
		} else {
			return false, Field{}
		}
	}

	return false, Field{}
}

func (t *TSharkFields) Completions(prefix string, cb IPrefixCompleterCallback) {
	var err error
	res := make([]string, 0, 100)

	t.once.Do(func() {
		err = t.Init()
	})

	if err != nil {
		log.Warnf("Field completion error: %v", err)
	}

	// might be nil if I am still loading from tshark -G
	if t.ser == nil {
		cb.Call(res)
		return
	}

	field := ""
	txt := prefix
	if !strings.HasSuffix(txt, " ") && txt != "" {
		fields := strings.Fields(txt)
		if len(fields) > 0 {
			field = fields[len(fields)-1]
		}
	}

	fields := strings.SplitN(field, ".", 2)

	prefs := make([]string, 0, 10)
	cur := t.ser.Fields.(map[string]interface{})
	failed := false
loop:
	for i := 0; i < len(fields); i++ {
		if val, ok := cur[fields[i]]; ok {
			if i == len(fields)-1 {
				switch val.(type) {
				// means there's another level of indirection, so our input is too long
				case map[string]interface{}:
					failed = true
				}
			} else {
				switch val := val.(type) {
				case map[string]interface{}:
					prefs = append(prefs, fields[i])
					cur = val
				default:
					failed = true
					break loop
				}
			}
		}
	}

	if !failed {
		for k, _ := range cur {
			if strings.HasPrefix(k, fields[len(fields)-1]) {
				res = append(res, strings.Join(append(prefs, k), "."))
			}
		}
	}
	for k, _ := range t.ser.Protocols {
		if strings.HasPrefix(k, field) {
			res = append(res, k)
		}
	}

	sort.Strings(res)
	res = dedup(res)

	cb.Call(res)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
