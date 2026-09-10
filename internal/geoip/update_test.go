package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateFromReplacesValidatedTable(t *testing.T) {
	const name = "GeoLite2-ASN-Blocks-IPv4.csv"
	body := "network,autonomous_system_number,autonomous_system_organization\n" +
		"203.0.113.0/24,64500,Example Network\n" + strings.Repeat("# padding\n", 8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer ts.Close()
	dir := t.TempDir()
	if err := updateFrom(context.Background(), ts.Client(), ts.URL, dir, []string{name}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("table mismatch: %q", got)
	}
}

func TestUpdateFromKeepsOldTableOnInvalidResponse(t *testing.T) {
	const name = "GeoLite2-ASN-Blocks-IPv4.csv"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not csv")) }))
	defer ts.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateFrom(context.Background(), ts.Client(), ts.URL, dir, []string{name}, nil); err == nil {
		t.Fatal("invalid response was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("old table was not preserved: %q, %v", got, err)
	}
}
