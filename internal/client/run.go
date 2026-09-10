package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// Progress is called after each finished attempt.
type Progress func(done, total int, a *Attempt)

// Run executes every plan Repeat times in a random order with jitter, then
// fetches observations and merges them. It returns all attempts.
func (c *Client) Run(ctx context.Context, plans []Plan, progress Progress) ([]*Attempt, error) {
	type job struct {
		p     Plan
		round int
	}
	var jobs, tail []job
	for r := 1; r <= c.opt.Repeat; r++ {
		round := make([]job, 0, len(plans))
		for _, p := range plans {
			if p.Last {
				tail = append(tail, job{p, r})
				continue
			}
			round = append(round, job{p, r})
		}
		rand.Shuffle(len(round), func(i, j int) { round[i], round[j] = round[j], round[i] })
		jobs = append(jobs, round...)
	}
	// The tail is ordered by what it may leave behind: the Tor handshakes
	// first (every round), then the burst controls, then the bursts that are
	// meant to provoke a freeze, last of all. A provoked freeze can thus
	// only taint later chrome bursts, never a control.
	sort.SliceStable(tail, func(i, j int) bool { return tailRank(tail[i].p) < tailRank(tail[j].p) })
	total := len(jobs) + len(tail)
	// The retry rounds enter total the moment they become foreseeable, not
	// when they start: the first failure of a port group in the rounds that
	// count means every plan of the group runs Retry more times (retryRounds
	// below re-runs exactly those: the tail's plans on a failure of a tail
	// attempt, the others on a failure of any other). A total that learned
	// this only at the end of the round sent the embedder's progress bar
	// from full back to half; this way it slows down instead. retryRounds
	// reconciles the guess with the rounds it actually builds.
	type retryKey struct {
		last  bool
		group string
	}
	plansOf := map[retryKey]int{}
	for _, p := range plans {
		plansOf[retryKey{p.Last, p.Group}]++
	}
	var (
		mu       sync.Mutex
		attempts []*Attempt
		done     int
		foreseen = map[retryKey]bool{}
		foretold = map[bool]int{} // retry attempts added to total so far, per phase kind (tail or not)
		poolsMu  sync.Mutex
		pools    = map[string]*sync.Mutex{}
	)
	pool := func(key string) *sync.Mutex {
		poolsMu.Lock()
		defer poolsMu.Unlock()
		m, ok := pools[key]
		if !ok {
			m = &sync.Mutex{}
			pools[key] = m
		}
		return m
	}
	worker := func(wg *sync.WaitGroup, queue chan job) {
		defer wg.Done()
		for j := range queue {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Duration(250+rand.Intn(1000)) * time.Millisecond)
			a := newAttempt(j.p.TestID, j.p.Group, j.p.Role, j.p.Variant, j.p.Transport, j.p.Port, j.round)
			func() {
				if j.p.serial != "" {
					m := pool(j.p.serial)
					m.Lock()
					defer m.Unlock()
				}
				defer func() {
					if r := recover(); r != nil {
						a.fail(OutcomeServerError, fmt.Errorf("panic: %v", r))
					}
				}()
				j.p.run(ctx, c, a)
			}()
			// An attempt in flight when the scan stopped (Stop, or the scan
			// deadline) failed because of that, not because of the path: its
			// timeout or reset must not reach a cell.
			if ctx.Err() != nil && a.Outcome != OutcomeOK {
				a.Outcome = OutcomeSkipped
				a.Detail["cancelled"] = "true"
			}
			mu.Lock()
			attempts = append(attempts, a)
			done++
			if c.opt.Retry > 0 && j.round <= c.opt.Repeat && a.Outcome != OutcomeOK && a.Outcome != OutcomeSkipped {
				if k := (retryKey{j.p.Last, a.Group}); !foreseen[k] {
					foreseen[k] = true
					n := c.opt.Retry * plansOf[k]
					total += n
					foretold[k.last] += n
				}
			}
			d, t := done, total
			mu.Unlock()
			if progress != nil {
				progress(d, t, a)
			}
		}
	}
	runPhase := func(js []job, parallel int) {
		var wg sync.WaitGroup
		queue := make(chan job)
		for i := 0; i < parallel; i++ {
			wg.Add(1)
			go worker(&wg, queue)
		}
		for _, j := range js {
			select {
			case queue <- j:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		close(queue)
		wg.Wait()
	}
	// Retry rounds: only the port groups that had a failure run again, so
	// that a failed cell and the controls the classifier compares it with on
	// the same port reach the three samples a confident verdict needs, while
	// a clean port stays at one attempt (the quick profile: 1 round + 2).
	// failedGroups lists the port groups with a failed attempt; with only
	// non-nil, just failures of those tests count.
	failedGroups := func(only map[string]bool) map[string]bool {
		out := map[string]bool{}
		mu.Lock()
		defer mu.Unlock()
		for _, a := range attempts {
			if only != nil && !only[a.TestID] {
				continue
			}
			if a.Outcome != OutcomeOK && a.Outcome != OutcomeSkipped {
				out[a.Group] = true
			}
		}
		return out
	}
	retryRounds := func(last bool, failed map[string]bool) []job {
		var retries []job
		for r := c.opt.Repeat + 1; r <= c.opt.Repeat+c.opt.Retry; r++ {
			round := make([]job, 0, len(plans))
			for _, p := range plans {
				if p.Last == last && failed[p.Group] {
					round = append(round, job{p, r})
				}
			}
			if last {
				sort.SliceStable(round, func(i, j int) bool { return tailRank(round[i].p) < tailRank(round[j].p) })
			} else {
				rand.Shuffle(len(round), func(i, j int) { round[i], round[j] = round[j], round[i] })
			}
			retries = append(retries, round...)
		}
		// The failures foretold these attempts one by one; a difference
		// means the rule above and this one drifted apart, and the real
		// count wins.
		mu.Lock()
		total += len(retries) - foretold[last]
		mu.Unlock()
		return retries
	}
	runPhase(jobs, c.opt.Parallel)
	if c.opt.Retry > 0 && ctx.Err() == nil {
		if retries := retryRounds(false, failedGroups(nil)); len(retries) > 0 {
			runPhase(retries, c.opt.Parallel)
		}
	}
	// The tail runs alone and serially: nothing else must be in flight while
	// a rate rule is being provoked, and one provoked freeze must not overlap
	// the next attempt.
	runPhase(tail, 1)
	// The tail's own retries, the same way but only where a tail cell itself
	// failed (its port group is shared with everything else on 443): those
	// cells (the Tor shapes, the bursts) are otherwise stuck at one sample in
	// the quick profile, and a verdict on them could never rise above low.
	if c.opt.Retry > 0 && ctx.Err() == nil && len(tail) > 0 {
		lastTests := map[string]bool{}
		for _, p := range plans {
			if p.Last {
				lastTests[p.TestID] = true
			}
		}
		if retries := retryRounds(true, failedGroups(lastTests)); len(retries) > 0 {
			runPhase(retries, 1)
		}
	}
	sort.SliceStable(attempts, func(i, j int) bool { return attempts[i].StartedAt.Before(attempts[j].StartedAt) })

	if c.standalone {
		for _, a := range attempts {
			a.Merged = mergeVerdict(a)
		}
		return attempts, nil
	}
	// A scan that ran into its own deadline still deserves the server's half
	// for the attempts that completed, so the fetch gets a short window of
	// its own instead of the expired ctx. A scan the caller stopped is not
	// worth that wait. Without observations the attempts stay unmerged:
	// "the server did not see it" must never stand for "the server was not
	// asked".
	fetchCtx := ctx
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), observationsGrace)
		defer cancel()
	} else if ctx.Err() == nil {
		// Give the server a moment to close lingering flows, then merge.
		time.Sleep(1500 * time.Millisecond)
	}
	obs, err := c.Observations(fetchCtx)
	if err != nil {
		return attempts, fmt.Errorf("observations: %w", err)
	}
	mergeObservations(attempts, obs, c.ClockSkew)
	for _, a := range attempts {
		a.Merged = mergeVerdict(a)
	}
	return attempts, nil
}

// observationsGrace bounds the observation fetch of a scan that hit its
// deadline.
const observationsGrace = 10 * time.Second

// tailRank orders the serial tail: Tor tests, then burst controls, then the
// provoking bursts.
func tailRank(p Plan) int {
	switch {
	case p.TestID == "tls.burst" && p.Role == RoleControl:
		return 1
	case p.TestID == "tls.burst":
		return 2
	}
	return 0
}
