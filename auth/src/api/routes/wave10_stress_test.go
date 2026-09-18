package routes

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).
//
// This file owns the routes package's Wave 10 adversarial coverage: session
// refresh races (concurrent get-session reads racing a due refresh write),
// deferred read-only bursts, and refresh-due predicate fuzzing.
//
// Upstream references (pinned Better Auth v1.7.5 at 5468e6bf):
//   - packages/better-auth/src/api/routes/session.ts (findSession refresh
//     write, deferSessionRefresh read-only mode, ?disableRefresh knob,
//     dont_remember persistence marker, expired-row deletion)
//
// Work limits pinned for this file: bursts are fixed at 16 racers;
// refresh-due fuzz inputs are pure (no I/O) and unbounded-cheap. No
// production code is changed here.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// Concurrent get-session reads racing a due refresh: every reader is served
// the same session, the row survives, and expiry never moves backwards. The
// refresh write itself is best-effort under concurrency (last-writer-wins on
// the same extension), but service must never fail, duplicate, or regress.
func TestWave10_SessionRefreshRace(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	token := "tok-w10-refresh-race"
	seedSessionUser(t, db, "w10-refresh@example.com", token, time.Now().UTC().Add(30*time.Minute))

	before, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || before == nil {
		t.Fatalf("seed lookup: %v %v", before, err)
	}
	beforeExp := sessionExpiresAt(before)
	if beforeExp.IsZero() {
		t.Fatal("seeded session must carry an expiry")
	}

	const racers = 16
	var served atomic.Int64
	var refreshed atomic.Int64
	var failed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionRow, userRow, wasRefreshed, _, err := loadSessionWithRefresh(ctx, opts, token, sessionRefreshConfig{})
			if err != nil || sessionRow == nil || userRow == nil {
				failed.Add(1)
				return
			}
			if stringField(sessionRow, "token") != token {
				failed.Add(1)
				return
			}
			served.Add(1)
			if wasRefreshed {
				refreshed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("refresh race failures = %d, want 0", failed.Load())
	}
	if served.Load() != racers {
		t.Fatalf("refresh race served = %d, want %d", served.Load(), racers)
	}
	t.Logf("refresh race: %d/%d readers performed the refresh write", refreshed.Load(), racers)

	after, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || after == nil {
		t.Fatalf("post-race lookup: %v %v", after, err)
	}
	if afterExp := sessionExpiresAt(after); afterExp.Before(beforeExp) {
		t.Fatalf("expiry regressed under race: %v -> %v", beforeExp, afterExp)
	}
}

// Deferred read-only bursts never write: every concurrent reader reports the
// due refresh via needsRefresh while the stored expiry stays byte-identical.
func TestWave10_SessionDeferredReadBurst(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	token := "tok-w10-deferred-race"
	seedSessionUser(t, db, "w10-deferred@example.com", token, time.Now().UTC().Add(30*time.Minute))

	before, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || before == nil {
		t.Fatalf("seed lookup: %v %v", before, err)
	}
	beforeExp := sessionExpiresAt(before)

	const racers = 16
	var due atomic.Int64
	var wrote atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionRow, _, wasRefreshed, needsRefresh, err := loadSessionWithRefresh(ctx, opts, token, sessionRefreshConfig{readOnly: true})
			if err != nil || sessionRow == nil {
				return
			}
			if wasRefreshed {
				wrote.Add(1)
			}
			if needsRefresh {
				due.Add(1)
			}
		}()
	}
	wg.Wait()
	if wrote.Load() != 0 {
		t.Fatalf("read-only burst performed %d writes, want 0", wrote.Load())
	}
	if due.Load() != racers {
		t.Fatalf("read-only burst due reports = %d, want %d", due.Load(), racers)
	}
	after, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || after == nil {
		t.Fatalf("post-burst lookup: %v %v", after, err)
	}
	if afterExp := sessionExpiresAt(after); !afterExp.Equal(beforeExp) {
		t.Fatalf("read-only burst moved expiry: %v -> %v", beforeExp, afterExp)
	}
}

// FuzzWave10_SessionRefreshDue fuzzes the pure refresh-due predicate: it
// never panics, disable flags always suppress, zero expiries never refresh,
// and evaluation is deterministic.
func FuzzWave10_SessionRefreshDue(f *testing.F) {
	f.Add(int64(1999999999), false)
	f.Add(int64(0), false)
	f.Add(int64(1), true)
	f.Fuzz(func(t *testing.T, expiresUnix int64, disableRefresh bool) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		// Unix 0 is 1970-01-01 (a real, long-past expiry), not the zero
		// time: model "no expiry" as a missing key, which is what
		// sessionExpiresAt reports as zero.
		row := map[string]any{}
		if expiresUnix != 0 {
			row["expiresAt"] = time.Unix(expiresUnix, 0).UTC()
		}
		now := time.Now().UTC()
		got := sessionRefreshDue(row, opts, disableRefresh, now)
		if again := sessionRefreshDue(row, opts, disableRefresh, now); again != got {
			t.Fatal("nondeterministic refresh-due evaluation")
		}
		if disableRefresh && got {
			t.Fatal("disableRefresh must suppress the refresh")
		}
		if expiresUnix == 0 && got {
			t.Fatal("missing expiry must never be refresh-due")
		}
	})
}
