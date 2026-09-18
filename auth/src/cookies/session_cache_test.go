package cookies

import (
	"testing"
	"time"
)

func TestCookieCacheRefreshThreshold(t *testing.T) {
	cases := []struct {
		name        string
		enabled     bool
		updateAge   int
		maxAge      time.Duration
		wantOK      bool
		wantSeconds float64
	}{
		{"disabled reports unset", false, 0, 5 * time.Minute, false, 0},
		{"default is 20 percent of maxAge", true, 0, 300 * time.Second, true, 60},
		{"custom updateAge wins", true, 30, 300 * time.Second, true, 30},
		{"non-positive maxAge defaults to 5m", true, 0, 0, true, 60},
		{"negative maxAge defaults to 5m", true, 0, -time.Minute, true, 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CookieCacheRefreshThreshold(tc.enabled, tc.updateAge, tc.maxAge)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Seconds() != tc.wantSeconds {
				t.Errorf("threshold = %v, want %vs", got, tc.wantSeconds)
			}
		})
	}
	if DefaultCookieCacheVersion != "1" {
		t.Errorf("DefaultCookieCacheVersion = %q, want %q (upstream default)", DefaultCookieCacheVersion, "1")
	}
}
