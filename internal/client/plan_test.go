package client

import (
	"testing"

	"github.com/xarvel/CensorPulseCli/internal/model"
)

func TestCatalogIncludesExplicitDoHFeature(t *testing.T) {
	c := &Client{
		opt:     Options{Tests: []string{"dns.doh"}},
		Params:  model.Params{Features: []string{"doh"}},
		Session: model.SessionResponse{}, // DoH is a feature, not a granted dispatcher test.
	}
	plans := c.Catalog()
	if len(plans) != 1 || plans[0].TestID != "dns.doh" {
		t.Fatalf("explicit dns.doh produced plans %+v", plans)
	}
}
