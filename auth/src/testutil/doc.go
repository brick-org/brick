// Package testutil loads the checked-in golden vectors under
// auth/src/testdata and verifies them against the Go helpers.
//
// Every test here is hermetic: stub HTTP transports and httptest servers
// only, no network.
package testutil
