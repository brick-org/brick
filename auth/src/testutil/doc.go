// Package testutil loads the checked-in golden vectors under
// auth/src/testdata and verifies them against the Go helpers in both
// directions (Go-write/TS-read, TS-write/Go-read).
//
// Every test here is hermetic: stub HTTP transports and httptest servers
// only, no network. The single opt-in live check in live_test.go is gated
// on BRICK_AUTH_LIVE_SMOKE=1 and never runs in normal CI.
//
// Provenance for each fixture (upstream file, upstream test, pinned commit,
// generation command) lives in auth/src/testdata/provenance.json and is
// summarized in auth/src/testdata/README.md (AUTH-R5-04).
package testutil
