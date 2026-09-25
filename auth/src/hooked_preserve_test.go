package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src"
)

// TestHookedPreserve_FiresDeleteHooksWithoutDeleting mirrors upstream
func TestHookedPreserve_FiresDeleteHooksWithoutDeleting(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	now := time.Now().UTC()
	if _, err := inner.Create(ctx, "session", map[string]any{
		"id": "s1", "userId": "u1", "token": "tok",
		"expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	var deleteAfter, updateAfter int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"session": {
			Delete: auth.OperationHooks{
				After: func(_ context.Context, _ map[string]any) error {
					deleteAfter++
					return nil
				},
			},
			Update: auth.OperationHooks{
				After: func(_ context.Context, _ map[string]any) error {
					updateAfter++
					return nil
				},
			},
		},
	})
	preserver, ok := wrapped.(interface {
		EndPreservedSessions(context.Context, string, []auth.Where, map[string]any) (int, error)
	})
	if !ok {
		t.Fatal("HookedAdapter must expose EndPreservedSessions")
	}
	n, err := preserver.EndPreservedSessions(ctx, "session",
		[]auth.Where{{Field: "token", Value: "tok"}}, map[string]any{"expiresAt": now, "updatedAt": now})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("preserved count = %d, want 1", n)
	}
	if deleteAfter != 1 {
		t.Fatalf("delete after-hooks fired %d times, want 1", deleteAfter)
	}
	if updateAfter != 0 {
		t.Fatalf("update after-hooks fired %d times, want 0", updateAfter)
	}
	row, err := inner.FindOne(ctx, "session", []auth.Where{{Field: "id", Value: "s1"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("preserved row must survive: %v", err)
	}
	if exp, _ := row["expiresAt"].(time.Time); exp.After(time.Now().UTC()) {
		t.Fatalf("preserved row must be ended, expiresAt=%v", exp)
	}
}
