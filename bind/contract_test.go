package cpprobe

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/CensorPulseCli/internal/report"
)

var update = flag.Bool("update", false, "rewrite the contract goldens in testdata/")

// The report JSON and the default config are the contract with the app, whose
// TypeScript types are written by hand. These goldens make every change to
// that contract visible: report.full.json has every field of every struct the
// report can carry (so a field Go adds and TypeScript lacks shows up), and
// report.min.json is the emptiest report (so a field TypeScript requires and Go
// may omit shows up). The app generates a type-checked file from them
// (mobile/scripts/gen-contract.mjs). After an intended change:
//
//	go test ./bind -run TestContractGoldens -update
func TestContractGoldens(t *testing.T) {
	full := &report.Report{}
	fill(reflect.ValueOf(full).Elem(), "", 0)
	var fullJSON, minJSON bytes.Buffer
	if err := full.WriteJSON(&fullJSON); err != nil {
		t.Fatal(err)
	}
	// The engine stamps the schema version on every report; the rest is zero.
	if err := (&report.Report{SchemaVersion: full.SchemaVersion}).WriteJSON(&minJSON); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{
		"report.full.json":    fullJSON.Bytes(),
		"report.min.json":     minJSON.Bytes(),
		"config.default.json": []byte(DefaultConfig() + "\n"),
	} {
		path := filepath.Join("testdata", name)
		if *update {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to create it)", err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s is out of date: the JSON contract with the app changed.\nIf that is intended: go test ./bind -run TestContractGoldens -update, then in mobile/: npm run gen-contract && npm run typecheck", name)
		}
	}
}

// Values for the fields the app types as a closed set rather than a string.
var (
	contractStrings = map[string]string{"mode": "sites", "confidence": "high", "outcome": "ok", "role": "baseline"}
	contractMapKeys = map[string]string{"stages_ms": "connect", "layers": "dns"}
	contractTime    = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

// fill sets every exported field reachable from v to a non-zero value, so
// that no omitempty field is left out of the JSON. name is the JSON name of
// the field v came from.
func fill(v reflect.Value, name string, depth int) {
	if depth > 8 {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), name, depth+1)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(contractTime))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag == "-" {
				continue
			}
			fill(v.Field(i), tag, depth+1)
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), name, depth+1)
		v.Set(s)
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fill(v.Index(i), name, depth+1)
		}
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k := reflect.New(v.Type().Key()).Elem()
		if k.Kind() == reflect.String {
			key := contractMapKeys[name]
			if key == "" {
				key = "k"
			}
			k.SetString(key)
		} else {
			fill(k, "", depth+1)
		}
		e := reflect.New(v.Type().Elem()).Elem()
		fill(e, "", depth+1)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.String:
		s := contractStrings[name]
		if s == "" {
			s = "s"
		}
		v.SetString(s)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	}
}
