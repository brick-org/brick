package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestdataDir returns the absolute path of auth/testdata.
func TestdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

// MustLoad reads testdata/<rel> into v, failing the test on any error.
// Malformed fixture files fail closed here so a corrupt vector can never
// silently pass.
func MustLoad(t *testing.T, rel string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(TestdataDir(t), rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse fixture %s: %v", rel, err)
	}
}

// MustLoadRaw reads testdata/<rel> as bytes, failing the test on error.
func MustLoadRaw(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(TestdataDir(t), rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return raw
}
