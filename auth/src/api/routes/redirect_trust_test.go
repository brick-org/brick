package routes

// Helpers extracted from repeated route logic: trust-request resolution and
// verification-row candidate keys.

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func TestRedirectTrust_ResolvesStoredRequestFirst(t *testing.T) {
	want, _ := http.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	ctx := context.WithValue(context.Background(), storedRequestKey{}, want)
	if got := trustRequest(ctx); got != want {
		t.Fatalf("trustRequest must prefer the stored request, got %v", got)
	}
}

func TestRedirectTrust_FallsBackToRebuild(t *testing.T) {
	ctx := context.Background()
	if got := trustRequest(ctx); got != callbackRequest(ctx) {
		t.Fatalf("trustRequest fallback must equal callbackRequest, got %v", got)
	}
}

func TestVerificationCandidates_PlainAndHashed(t *testing.T) {
	option := resolveVerificationStoreOption("delete-account-tok", types.VerificationStoreIdentifier{})
	stored, err := processVerificationIdentifier("delete-account-tok", option)
	if err != nil {
		t.Fatalf("identifier: %v", err)
	}
	got := verificationCandidates(option, "delete-account-tok", stored)
	if len(got) == 0 || got[0] != stored {
		t.Fatalf("stored key must come first, got %v", got)
	}
	for _, c := range got {
		if c == "" {
			t.Fatalf("candidate keys must be non-empty, got %v", got)
		}
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatalf("candidate keys must be distinct, got %v", got)
		}
		seen[c] = true
	}
	if !reflect.DeepEqual(got, append([]string{stored}, got[1:]...)) {
		t.Fatalf("stored key must stay first, got %v", got)
	}
}
