// Package geoip maps an IP address to its autonomous system and country from
// the GeoLite2 CSV tables, entirely offline. The client uses it to record the
// network a scan was taken from (the address itself comes from the probe's
// control API), so that reports can be grouped per carrier without asking any
// third-party service.
//
// Expected files (as published on the "release" branch of
// github.com/Loyalsoldier/geoip; scripts/geoip-update.sh fetches them):
//
//	GeoLite2-ASN-Blocks-IPv4.csv       network,autonomous_system_number,autonomous_system_organization
//	GeoLite2-ASN-Blocks-IPv6.csv       (optional)
//	GeoLite2-Country-Blocks-IPv4.csv   network,geoname_id,registered_country_geoname_id,...
//	GeoLite2-Country-Blocks-IPv6.csv   (optional)
//	GeoLite2-Country-Locations-en.csv  geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,...
package geoip

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// Info is what a lookup yields; zero fields mean "not in the tables".
type Info struct {
	ASN     int    `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	Prefix  string `json:"prefix,omitempty"`  // the ASN table row that matched
}

type asnRow struct {
	prefix netip.Prefix
	asn    int
	org    string
}

type countryRow struct {
	prefix  netip.Prefix
	country string
}

// DB holds the parsed tables.
type DB struct {
	asn     []asnRow
	country []countryRow
	// Updated is the newest modification time among the files that were read.
	Updated time.Time
	// Files lists what was loaded, for the report.
	Files []string
}

var ErrNoTables = errors.New("geoip: no GeoLite2 CSV tables found")

// Load reads the tables found in dir. Missing IPv6 tables are tolerated;
// a missing IPv4 ASN table is an error.
func Load(dir string) (*DB, error) {
	db := &DB{}
	add := func(name string, parse func(*csv.Reader) error, required bool) error {
		p := filepath.Join(dir, name)
		f, err := os.Open(p)
		if err != nil {
			if required {
				return err
			}
			return nil
		}
		defer f.Close()
		if st, err := f.Stat(); err == nil && st.ModTime().After(db.Updated) {
			db.Updated = st.ModTime()
		}
		r := csv.NewReader(f)
		r.ReuseRecord = true
		r.FieldsPerRecord = -1
		if _, err := r.Read(); err != nil { // header
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := parse(r); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		db.Files = append(db.Files, name)
		return nil
	}
	parseASN := func(r *csv.Reader) error {
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if len(rec) < 3 {
				continue
			}
			pfx, err := netip.ParsePrefix(rec[0])
			if err != nil {
				continue
			}
			n, _ := strconv.Atoi(rec[1])
			db.asn = append(db.asn, asnRow{prefix: pfx.Masked(), asn: n, org: rec[2]})
		}
	}
	if err := add("GeoLite2-ASN-Blocks-IPv4.csv", parseASN, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoTables
		}
		return nil, err
	}
	if err := add("GeoLite2-ASN-Blocks-IPv6.csv", parseASN, false); err != nil {
		return nil, err
	}
	// Country: blocks reference geoname ids; the locations table maps those
	// to ISO codes. Read locations first.
	iso := map[string]string{}
	if err := add("GeoLite2-Country-Locations-en.csv", func(r *csv.Reader) error {
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if len(rec) >= 5 && rec[4] != "" {
				iso[rec[0]] = rec[4]
			}
		}
	}, false); err != nil {
		return nil, err
	}
	parseCountry := func(r *csv.Reader) error {
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if len(rec) < 3 {
				continue
			}
			pfx, err := netip.ParsePrefix(rec[0])
			if err != nil {
				continue
			}
			// geoname_id is the located country; registered_country is the
			// fallback GeoLite2 itself uses when the first is empty.
			code := iso[rec[1]]
			if code == "" {
				code = iso[rec[2]]
			}
			if code == "" {
				continue
			}
			db.country = append(db.country, countryRow{prefix: pfx.Masked(), country: code})
		}
	}
	if len(iso) > 0 {
		if err := add("GeoLite2-Country-Blocks-IPv4.csv", parseCountry, false); err != nil {
			return nil, err
		}
		if err := add("GeoLite2-Country-Blocks-IPv6.csv", parseCountry, false); err != nil {
			return nil, err
		}
	}
	// Longest prefix wins: sort by prefix length descending so that the
	// first match in a linear scan is the most specific one.
	sort.SliceStable(db.asn, func(i, j int) bool { return db.asn[i].prefix.Bits() > db.asn[j].prefix.Bits() })
	sort.SliceStable(db.country, func(i, j int) bool { return db.country[i].prefix.Bits() > db.country[j].prefix.Bits() })
	return db, nil
}

// Lookup returns what the tables know about ip. A linear scan over a few
// hundred thousand prefixes takes milliseconds; the client does it once.
func (db *DB) Lookup(ip netip.Addr) Info {
	var out Info
	if db == nil || !ip.IsValid() {
		return out
	}
	ip = ip.Unmap()
	for _, r := range db.asn {
		if r.prefix.Addr().Is4() == ip.Is4() && r.prefix.Contains(ip) {
			out.ASN, out.Org, out.Prefix = r.asn, r.org, r.prefix.String()
			break
		}
	}
	for _, r := range db.country {
		if r.prefix.Addr().Is4() == ip.Is4() && r.prefix.Contains(ip) {
			out.Country = r.country
			break
		}
	}
	return out
}

// Rows reports table sizes (for logs and tests).
func (db *DB) Rows() (asn, country int) { return len(db.asn), len(db.country) }

// DefaultDir is where scripts/geoip-update.sh puts the tables.
func DefaultDir() string {
	if d := os.Getenv("CPPROBE_GEOIP_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cpprobe", "geoip")
}
