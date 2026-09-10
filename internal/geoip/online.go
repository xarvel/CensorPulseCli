package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Online lookups ask a public geo-ASN API about the caller's own address.
// They are the fallback for a client that has no GeoLite2 tables (a phone)
// and no server to tell it its address (a standalone real-destinations
// scan). They are opt-in: the offline lookup never leaves the machine, and
// a report must say which source named the network. The address the API
// returns is discarded; only ASN, organisation and country are kept.

// OnlineSources are tried in order; the first that answers wins.
var OnlineSources = []OnlineSource{
	{Name: "ipwho.is", URL: "https://ipwho.is/?fields=success,country_code,connection", parse: parseIPWho},
	{Name: "ipapi.co", URL: "https://ipapi.co/json/", parse: parseIPAPI},
}

// OnlineSource is one public API.
type OnlineSource struct {
	Name  string
	URL   string
	parse func([]byte) (Info, error)
}

// LookupOnline resolves the caller's network through the first source that
// answers. The returned string names the source, for the report.
func LookupOnline(ctx context.Context, hc *http.Client) (Info, string, error) {
	return lookupOnline(ctx, hc, OnlineSources)
}

func lookupOnline(ctx context.Context, hc *http.Client, sources []OnlineSource) (Info, string, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 8 * time.Second}
	}
	var errs []string
	for _, s := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		if err != nil {
			errs = append(errs, s.Name+": "+err.Error())
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "cpprobe")
		resp, err := hc.Do(req)
		if err != nil {
			errs = append(errs, s.Name+": "+err.Error())
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			errs = append(errs, s.Name+": "+err.Error())
			continue
		}
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Sprintf("%s: http %d", s.Name, resp.StatusCode))
			continue
		}
		info, err := s.parse(body)
		if err != nil {
			errs = append(errs, s.Name+": "+err.Error())
			continue
		}
		return info, s.Name, nil
	}
	return Info{}, "", errors.New("online geoip: " + strings.Join(errs, "; "))
}

func parseIPWho(b []byte) (Info, error) {
	var v struct {
		Success     *bool  `json:"success"`
		CountryCode string `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return Info{}, err
	}
	if v.Success != nil && !*v.Success {
		return Info{}, errors.New("success=false")
	}
	if v.Connection.ASN == 0 {
		return Info{}, errors.New("no asn")
	}
	org := v.Connection.ISP
	if org == "" {
		org = v.Connection.Org
	}
	return Info{ASN: v.Connection.ASN, Org: org, Country: strings.ToUpper(v.CountryCode)}, nil
}

func parseIPAPI(b []byte) (Info, error) {
	var v struct {
		Error       bool   `json:"error"`
		ASN         string `json:"asn"` // "AS8359"
		Org         string `json:"org"`
		CountryCode string `json:"country_code"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return Info{}, err
	}
	if v.Error {
		return Info{}, errors.New("error=true")
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(v.ASN), "AS"))
	if err != nil || n == 0 {
		return Info{}, errors.New("no asn")
	}
	return Info{ASN: n, Org: v.Org, Country: strings.ToUpper(v.CountryCode)}, nil
}
