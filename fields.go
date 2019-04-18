// Copyright 2019 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package termshark

import (
	"bufio"
	"os/exec"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

//======================================================================

type mapOrString struct {
	// Need to be exported for mapOrString to be serializable
	M map[string]*mapOrString
}

type TSharkFields struct {
	once   sync.Once
	fields *mapOrString
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

// Can be run asynchronously.
// This ought to use interfaces to make it testable.
func (w *TSharkFields) Init() error {
	newer, err := FileNewerThan(CacheFile("tsharkfields.gob.gz"), DirOfPathCommandUnsafe(TSharkBin()))
	if err == nil {
		if newer {
			f := &mapOrString{}
			err = ReadGob(CacheFile("tsharkfields.gob.gz"), f)
			if err == nil {
				w.fields = f
				log.Infof("Read cached tshark fields.")
				return nil
			} else {
				log.Infof("Could not read cached tshark fields (%v) - regenerating...", err)
			}
		}
	}

	cmd := exec.Command(TSharkBin(), []string{"-G", "fields"}...)

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	cmd.Start()

	top := &mapOrString{
		M: make(map[string]*mapOrString),
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "F") {
			fields := strings.Split(line, "\t")
			field := fields[2]
			protos := strings.Split(field, ".")
			cur := top
			for i := 0; i < len(protos); i++ {
				if val, ok := cur.M[protos[i]]; ok {
					cur = val
				} else {
					next := &mapOrString{
						M: make(map[string]*mapOrString),
					}
					cur.M[protos[i]] = next
					cur = next
				}
			}
		} else if strings.HasPrefix(line, "P") {
			fields := strings.Split(line, "\t")
			field := fields[2]
			if _, ok := top.M[field]; !ok {
				next := &mapOrString{
					M: make(map[string]*mapOrString),
				}
				top.M[field] = next
			}
		}
	}

	cmd.Wait()

	err = WriteGob(CacheFile("tsharkfields.gob.gz"), top)
	if err != nil {
		return err
	}

	w.fields = top

	return nil
}

func (t *TSharkFields) Completions(prefix string, cb IPrefixCompleterCallback) {
	var err error
	res := make([]string, 0, 100)

	t.once.Do(func() {
		err = t.Init()
	})

	if err != nil {
		log.Infof("Field completion error: %v", err)
	}

	if t.fields == nil {
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

	fields := strings.Split(field, ".")

	prefs := make([]string, 0, 10)
	cur := t.fields.M
	failed := false
	for i := 0; i < len(fields)-1; i++ {
		if cur == nil {
			failed = true
			break
		}
		if val, ok := cur[fields[i]]; ok && val != nil {
			prefs = append(prefs, fields[i])
			cur = val.M
		} else {
			failed = true
			break
		}
	}

	if !failed {
		for k, _ := range cur {
			if strings.HasPrefix(k, fields[len(fields)-1]) {
				res = append(res, strings.Join(append(prefs, k), "."))
			}
		}
	}

	sort.Strings(res)

	cb.Call(res)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
