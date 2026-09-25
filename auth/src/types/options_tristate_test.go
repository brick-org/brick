package types

import (
	"testing"
	"time"
)

// Tri-state contract pins (*bool/*int unset-vs-explicit).
//
//   - EmailVerificationOptions.SendOnSignUp is *bool: nil (unset) falls back
//     to EmailAndPassword.RequireEmailVerification; non-nil is explicit.
//     Upstream: `sendOnSignUp ?? requireEmailVerification` (sign-up.ts).
//   - SessionOptions.UpdateAge is *int: nil (unset) defaults to 24h;
//     explicit 0 means always-refresh; >0 is seconds. Upstream:
//     `updateAge?: number` with `!== undefined ? value : 86400`
//     (create-context.ts) and "If set 0 the session will be refreshed every
//     time it is used" (init-options.ts).

func f9BoolPtr(v bool) *bool { return &v }

func f9IntPtr(v int) *int { return &v }

func TestOptionsTristate_ResolveSendOnSignUp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		explicit *bool
		require  bool
		want     bool
	}{
		{"nil+false->false", nil, false, false},
		{"nil+true->true", nil, true, true},
		{"false+true->false (explicit wins)", f9BoolPtr(false), true, false},
		{"true+false->true (explicit wins)", f9BoolPtr(true), false, true},
		{"false+false->false", f9BoolPtr(false), false, false},
		{"true+true->true", f9BoolPtr(true), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveSendOnSignUp(tc.explicit, tc.require); got != tc.want {
				t.Fatalf("ResolveSendOnSignUp(%v, %v) = %v, want %v",
					tc.explicit, tc.require, got, tc.want)
			}
		})
	}
}

func TestOptionsTristate_SendOnSignUpZeroValueIsUnset(t *testing.T) {
	var opts EmailVerificationOptions
	if opts.SendOnSignUp != nil {
		t.Fatal("zero EmailVerificationOptions.SendOnSignUp must be nil (unset)")
	}
	if ResolveSendOnSignUp(opts.SendOnSignUp, false) {
		t.Fatal("unset SendOnSignUp with require=false must not send")
	}
	if !ResolveSendOnSignUp(opts.SendOnSignUp, true) {
		t.Fatal("unset SendOnSignUp with require=true must send")
	}
}

func TestOptionsTristate_ResolveUpdateAgeSeconds(t *testing.T) {
	if got := ResolveUpdateAgeSeconds(nil); got != 24*60*60 {
		t.Fatalf("nil UpdateAge = %d, want 86400 (24h default)", got)
	}
	if DefaultSessionUpdateAgeSeconds != 24*60*60 {
		t.Fatalf("DefaultSessionUpdateAgeSeconds = %d, want 86400", DefaultSessionUpdateAgeSeconds)
	}
	if got := ResolveUpdateAgeSeconds(f9IntPtr(0)); got != 0 {
		t.Fatalf("explicit 0 UpdateAge = %d, want 0 (always-refresh)", got)
	}
	if got := ResolveUpdateAgeSeconds(f9IntPtr(3600)); got != 3600 {
		t.Fatalf("explicit 3600 UpdateAge = %d, want 3600", got)
	}
}

func TestOptionsTristate_UpdateAgeDuration(t *testing.T) {
	var unset SessionOptions
	if unset.UpdateAge != nil {
		t.Fatal("zero SessionOptions.UpdateAge must be nil (unset)")
	}
	if got := unset.UpdateAgeDuration(); got != 24*time.Hour {
		t.Fatalf("unset UpdateAgeDuration = %v, want 24h", got)
	}
	always := SessionOptions{UpdateAge: f9IntPtr(0)}
	if got := always.UpdateAgeDuration(); got != 0 {
		t.Fatalf("explicit-0 UpdateAgeDuration = %v, want 0 (always-refresh)", got)
	}
	explicit := SessionOptions{UpdateAge: f9IntPtr(60)}
	if got := explicit.UpdateAgeDuration(); got != 60*time.Second {
		t.Fatalf("explicit-60 UpdateAgeDuration = %v, want 60s", got)
	}
}

func TestOptionsTristate_UpdateAgeValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options SessionOptions
		wantErr bool
	}{
		{"nil valid (unset)", SessionOptions{}, false},
		{"zero valid (always-refresh)", SessionOptions{UpdateAge: f9IntPtr(0)}, false},
		{"positive valid", SessionOptions{UpdateAge: f9IntPtr(1)}, false},
		{"negative rejected", SessionOptions{UpdateAge: f9IntPtr(-1)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.options.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error for negative Session.UpdateAge")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
