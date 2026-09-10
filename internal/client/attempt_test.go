package client

import (
	"context"
	"fmt"
	"net"
	"testing"
)

// A dial interrupted by the caller's cancel must not read as a reset: it is
// the scan that stopped, not the path that answered.
func TestClassifyNetErrCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var d net.Dialer
	_, err := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	if err == nil {
		t.Fatal("dial with a cancelled context succeeded")
	}
	for _, afterWrite := range []bool{false, true} {
		if got := classifyNetErr(err, afterWrite); got != OutcomeSkipped {
			t.Errorf("classifyNetErr(%v, afterWrite=%v) = %s, want %s", err, afterWrite, got, OutcomeSkipped)
		}
	}
	wrapped := fmt.Errorf("reserve: %w", context.Canceled)
	if got := classifyNetErr(wrapped, false); got != OutcomeSkipped {
		t.Errorf("wrapped context.Canceled = %s, want %s", got, OutcomeSkipped)
	}
}
