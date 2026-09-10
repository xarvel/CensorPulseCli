package client

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// The retry rounds enter the progress total when the failure that causes
// them is delivered, not when the round starts: by the time a retry attempt
// finishes, the total of its phase is final. The engine's progress bar
// (and the app's) used to run to 100% at the end of round one and drop to
// a third when the retries were added.
func TestRunForetellsRetryRoundsInTotal(t *testing.T) {
	ok := func(ctx context.Context, c *Client, a *Attempt) *Attempt { return a.ok() }
	bad := func(ctx context.Context, c *Client, a *Attempt) *Attempt {
		return a.fail(OutcomeConnectTimeout, errors.New("i/o timeout"))
	}
	plans := []Plan{
		{TestID: "tcp.echo", Group: "tcp/80", Role: RoleBaseline, Variant: "a", Transport: "tcp", Port: 80, run: ok},
		{TestID: "tcp.echo", Group: "tcp/80", Role: RoleVariant, Variant: "b", Transport: "tcp", Port: 80, run: ok},
		{TestID: "tcp.echo", Group: "tcp/443", Role: RoleBaseline, Variant: "a", Transport: "tcp", Port: 443, run: ok},
		{TestID: "tls.hello", Group: "tcp/443", Role: RoleVariant, Variant: "chrome", Transport: "tcp", Port: 443, run: bad},
		{TestID: "tor.handshake", Group: "tcp/443", Role: RoleVariant, Variant: "tor", Transport: "tcp", Port: 443, Last: true, run: ok},
		{TestID: "tls.burst", Group: "tcp/443", Role: RoleVariant, Variant: "chrome-x4", Transport: "tcp", Port: 443, Last: true, run: bad},
	}
	// Round one: 4 plans, then the tail of 2 (total 6). tls.hello fails, so
	// the two non-tail plans of tcp/443 run twice more (+4, total 10) before
	// the tail; tls.burst fails, so the two tail plans run twice more
	// (+4, total 14). tcp/80 is clean and stays at one attempt.
	c := &Client{opt: Options{Repeat: 1, Retry: 2, Parallel: 4}, standalone: true}
	var mu sync.Mutex
	var seen [][2]int
	attempts, err := c.Run(context.Background(), plans, func(done, total int, a *Attempt) {
		mu.Lock()
		seen = append(seen, [2]int{done, total})
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 14 || len(seen) != 14 {
		t.Fatalf("%d attempts, %d progress calls; want 14", len(attempts), len(seen))
	}
	// done and total are read under one lock, so each pair is consistent
	// whatever order the workers delivered them in.
	for _, p := range seen {
		done, total := p[0], p[1]
		var want []int
		switch {
		case done < 4: // round one, before or after the tls.hello failure
			want = []int{6, 10}
		case done == 4: // round one complete: its failure has been counted, the retries are in the total
			want = []int{10}
		case done <= 9: // the non-tail retries, then tor.handshake
			want = []int{10}
		case done == 10: // tls.burst, the failure that foretells the tail's retries
			want = []int{14}
		default: // the tail's retries
			want = []int{14}
		}
		found := false
		for _, w := range want {
			found = found || total == w
		}
		if !found {
			t.Errorf("progress %d/%d: total not in %v", done, total, want)
		}
	}
	last := seen[len(seen)-1]
	if last != [2]int{14, 14} {
		t.Errorf("last progress %v, want 14/14", last)
	}
	rounds := map[int]int{}
	for _, a := range attempts {
		rounds[a.Round]++
	}
	if rounds[1] != 6 || rounds[2] != 4 || rounds[3] != 4 {
		t.Errorf("attempts per round %v, want 6/4/4", rounds)
	}
}

// Without retries the total is the plan count from the first call on.
func TestRunTotalIsFixedWithoutRetries(t *testing.T) {
	ok := func(ctx context.Context, c *Client, a *Attempt) *Attempt { return a.ok() }
	bad := func(ctx context.Context, c *Client, a *Attempt) *Attempt {
		return a.fail(OutcomeConnectTimeout, errors.New("i/o timeout"))
	}
	plans := []Plan{
		{TestID: "tcp.echo", Group: "tcp/80", Role: RoleBaseline, Variant: "a", Transport: "tcp", Port: 80, run: ok},
		{TestID: "tls.hello", Group: "tcp/443", Role: RoleVariant, Variant: "chrome", Transport: "tcp", Port: 443, run: bad},
	}
	c := &Client{opt: Options{Repeat: 2, Retry: 0, Parallel: 2}, standalone: true}
	var mu sync.Mutex
	var totals []int
	attempts, err := c.Run(context.Background(), plans, func(done, total int, a *Attempt) {
		mu.Lock()
		totals = append(totals, total)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 4 {
		t.Fatalf("%d attempts, want 4", len(attempts))
	}
	for _, total := range totals {
		if total != 4 {
			t.Fatalf("totals %v, want all 4", totals)
		}
	}
}
