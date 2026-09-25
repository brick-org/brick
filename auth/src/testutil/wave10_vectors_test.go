package testutil

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).

import (
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// TestWave10_RedirectVectors asserts every shared redirect-trust vector against trusted-origins.ts.
func TestWave10_RedirectVectors(t *testing.T) {
	var doc struct {
		BaseURL        string   `json:"base_url"`
		TrustedOrigins []string `json:"trusted_origins"`
		Evil           []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Trusted bool   `json:"trusted"`
		} `json:"evil"`
		Safe []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Trusted bool   `json:"trusted"`
		} `json:"safe"`
	}
	MustLoad(t, "wave10_redirects.json", &doc)

	opts := types.Options{BaseURL: doc.BaseURL, TrustedOrigins: doc.TrustedOrigins}
	if len(doc.Evil) == 0 || len(doc.Safe) == 0 {
		t.Fatal("fixture must carry evil and safe rows")
	}
	for _, tc := range doc.Evil {
		if tc.Trusted {
			t.Errorf("fixture evil row %q (%q) marked trusted; vectors must stay fail-closed", tc.Name, tc.URL)
		}
		if types.IsTrustedRedirect(tc.URL, opts, nil) {
			t.Errorf("evil redirect %q (%q) trusted", tc.Name, tc.URL)
		}
		for _, p := range doc.TrustedOrigins {
			if types.MatchesOriginPattern(tc.URL, p) {
				t.Errorf("evil redirect %q (%q) matched pattern %q", tc.Name, tc.URL, p)
			}
		}
	}
	for _, tc := range doc.Safe {
		if !tc.Trusted {
			t.Errorf("fixture safe row %q (%q) marked untrusted; vectors must stay usable", tc.Name, tc.URL)
		}
		if !types.IsTrustedRedirect(tc.URL, opts, nil) {
			t.Errorf("safe redirect %q (%q) not trusted", tc.Name, tc.URL)
		}
	}
}

// TestWave10_RegistrationVectors pins the fixture shape contract and the fail-closed core.
func TestWave10_RegistrationVectors(t *testing.T) {
	var doc struct {
		Cases []struct {
			Name     string `json:"name"`
			URI      string `json:"uri"`
			WebOK    bool   `json:"web_ok"`
			NativeOK bool   `json:"native_ok"`
		} `json:"cases"`
	}
	MustLoad(t, "wave10_registration.json", &doc)
	if len(doc.Cases) == 0 {
		t.Fatal("fixture must carry cases")
	}
	for _, tc := range doc.Cases {
		if tc.Name == "" {
			t.Errorf("case missing name: %+v", tc)
		}
	}
	canonical, webAccepts, nativeOnly, dualReject := false, 0, 0, 0
	for _, tc := range doc.Cases {
		if tc.Name == "web https callback" && tc.WebOK && tc.NativeOK {
			canonical = true
		}
		switch {
		case tc.WebOK:
			webAccepts++
		case tc.NativeOK:
			nativeOnly++
		default:
			dualReject++
		}
	}
	if !canonical {
		t.Error("fixture must pin the canonical web+https accept vector")
	}
	if webAccepts == 0 || nativeOnly == 0 || dualReject == 0 {
		t.Errorf("fixture must cover web accepts (%d), native-only (%d), and dual rejects (%d)",
			webAccepts, nativeOnly, dualReject)
	}
}
