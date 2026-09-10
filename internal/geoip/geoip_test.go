package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func writeTables(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"GeoLite2-ASN-Blocks-IPv4.csv": "network,autonomous_system_number,autonomous_system_organization\n" +
			"1.0.0.0/24,13335,\"Cloudflare, Inc.\"\n" +
			"5.0.0.0/8,1,\"Big Block\"\n" +
			"5.1.0.0/16,2,\"Smaller Block\"\n",
		"GeoLite2-ASN-Blocks-IPv6.csv": "network,autonomous_system_number,autonomous_system_organization\n" +
			"2001:db8::/32,64500,\"Doc Net\"\n",
		"GeoLite2-Country-Locations-en.csv": "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
			"2017370,en,EU,Europe,RS,Serbia,0\n" +
			"2077456,en,OC,Oceania,AU,Australia,0\n",
		"GeoLite2-Country-Blocks-IPv4.csv": "network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast\n" +
			"1.0.0.0/24,,2077456,,0,0,\n" +
			"5.1.0.0/16,2017370,2017370,,0,0,\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLookupLongestPrefixAndCountryFallback(t *testing.T) {
	db, err := Load(writeTables(t))
	if err != nil {
		t.Fatal(err)
	}
	if a, c := db.Rows(); a != 4 || c != 2 {
		t.Fatalf("rows asn=%d country=%d", a, c)
	}
	got := db.Lookup(netip.MustParseAddr("5.1.2.3"))
	if got.ASN != 2 || got.Org != "Smaller Block" || got.Country != "RS" || got.Prefix != "5.1.0.0/16" {
		t.Errorf("longest prefix: %+v", got)
	}
	got = db.Lookup(netip.MustParseAddr("5.9.9.9"))
	if got.ASN != 1 || got.Country != "" {
		t.Errorf("/8 fallback: %+v", got)
	}
	// registered_country is used when geoname_id is empty (anycast rows)
	got = db.Lookup(netip.MustParseAddr("1.0.0.1"))
	if got.ASN != 13335 || got.Country != "AU" {
		t.Errorf("registered country fallback: %+v", got)
	}
	got = db.Lookup(netip.MustParseAddr("2001:db8::1"))
	if got.ASN != 64500 || got.Org != "Doc Net" {
		t.Errorf("ipv6: %+v", got)
	}
	if got := db.Lookup(netip.MustParseAddr("9.9.9.9")); got != (Info{}) {
		t.Errorf("miss should be empty: %+v", got)
	}
	if got := db.Lookup(netip.MustParseAddr("::ffff:5.1.2.3")); got.ASN != 2 {
		t.Errorf("mapped v4 should unmap: %+v", got)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(t.TempDir()); err != ErrNoTables {
		t.Fatalf("want ErrNoTables, got %v", err)
	}
}
