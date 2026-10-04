package appliance

import (
	"testing"
	"time"
)

func TestWindowAndRetryBounds(t *testing.T) {
	for _, tc := range []struct {
		hour    int
		allowed bool
	}{{1, false}, {2, true}, {3, true}, {4, false}} {
		at := time.Date(2026, 10, 3, tc.hour, 0, 0, 0, time.UTC)
		if DefaultMaintenanceWindow.Allows(at) != tc.allowed {
			t.Fatal("maintenance boundary", tc)
		}
	}
	overnight := MaintenanceWindow{StartMinuteUTC: 1380, EndMinuteUTC: 60}
	if !overnight.Allows(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)) || overnight.Allows(time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)) {
		t.Fatal("overnight window")
	}
	invalid := MaintenanceWindow{StartMinuteUTC: 0, EndMinuteUTC: 1440}
	if invalid.Allows(time.Now()) {
		t.Fatal("invalid window")
	}
	a := &Agent{}
	first := a.Next(ErrDenied)
	if first < 54*time.Second || first > 66*time.Second {
		t.Fatal("first backoff", first)
	}
	for range 20 {
		d := a.Next(ErrDenied)
		if d > time.Hour {
			t.Fatal("unbounded retry", d)
		}
	}
	d := a.Next(nil)
	if d < 13*time.Minute || d > 17*time.Minute {
		t.Fatal("poll jitter", d)
	}
}
