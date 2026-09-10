package geoip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupOnlineFallsThroughSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/who":
			w.Write([]byte(`{"success":false}`))
		case "/api":
			w.Write([]byte(`{"asn":"AS8359","org":"MTS PJSC","country_code":"ru"}`))
		default:
			http.Error(w, "no", 500)
		}
	}))
	defer srv.Close()
	sources := []OnlineSource{
		{Name: "dead", URL: srv.URL + "/dead", parse: parseIPWho},
		{Name: "who", URL: srv.URL + "/who", parse: parseIPWho},
		{Name: "api", URL: srv.URL + "/api", parse: parseIPAPI},
	}
	info, src, err := lookupOnline(t.Context(), srv.Client(), sources)
	if err != nil || src != "api" || info.ASN != 8359 || info.Country != "RU" || info.Org != "MTS PJSC" {
		t.Fatalf("got %+v %s %v", info, src, err)
	}
	if _, _, err := lookupOnline(t.Context(), srv.Client(), sources[:2]); err == nil {
		t.Fatal("expected an error when no source answers")
	}
	info, err = parseIPWho([]byte(`{"success":true,"country_code":"de","connection":{"asn":3320,"isp":"","org":"Deutsche Telekom"}}`))
	if err != nil || info.ASN != 3320 || info.Org != "Deutsche Telekom" || info.Country != "DE" {
		t.Fatalf("ipwho: %+v %v", info, err)
	}
}
