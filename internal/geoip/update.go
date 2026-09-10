package geoip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const tablesBaseURL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release"

var tableFiles = []string{
	"GeoLite2-ASN-Blocks-IPv4.csv",
	"GeoLite2-ASN-Blocks-IPv6.csv",
	"GeoLite2-Country-Blocks-IPv4.csv",
	"GeoLite2-Country-Blocks-IPv6.csv",
	"GeoLite2-Country-Locations-en.csv",
}

// Update downloads the GeoLite2 CSV tables used by the offline lookup. Each
// old table remains in place until its replacement has been downloaded and
// minimally validated.
func Update(ctx context.Context, dir string, progress func(name string, bytes int64)) error {
	return updateFrom(ctx, &http.Client{Timeout: 10 * time.Minute}, tablesBaseURL, dir, tableFiles, progress)
}

func updateFrom(ctx context.Context, hc *http.Client, baseURL, dir string, files []string, progress func(string, int64)) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range files {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/"+name, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "cpprobe-geoip-update/1")
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("download %s: %s", name, resp.Status)
		}
		tmp, err := os.CreateTemp(dir, "."+name+".*.part")
		if err != nil {
			resp.Body.Close()
			return err
		}
		tmpName := tmp.Name()
		n, copyErr := io.Copy(tmp, io.LimitReader(resp.Body, 512<<20))
		closeErr := tmp.Close()
		resp.Body.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(tmpName)
			if copyErr != nil {
				return fmt.Errorf("download %s: %w", name, copyErr)
			}
			return fmt.Errorf("write %s: %w", name, closeErr)
		}
		f, err := os.Open(tmpName)
		if err != nil {
			os.Remove(tmpName)
			return err
		}
		header, readErr := bufio.NewReader(f).ReadString('\n')
		f.Close()
		if readErr != nil || n < 100 || n >= 512<<20 || (!strings.Contains(header, "network") && !strings.Contains(header, "geoname_id")) {
			os.Remove(tmpName)
			return fmt.Errorf("download %s: response is not a GeoLite2 CSV table", name)
		}
		if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
			os.Remove(tmpName)
			return err
		}
		if progress != nil {
			progress(name, n)
		}
	}
	return nil
}
