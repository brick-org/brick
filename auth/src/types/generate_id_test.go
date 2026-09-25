package types

import (
	"strings"
	"testing"
)

// TestMintModelID_Default ports the default branch of upstream generateIdFunc
func TestMintModelID_Default(t *testing.T) {
	var opts Options
	id, ok := MintModelID(opts, "user", nil)
	if !ok || len(id) != 32 {
		t.Fatalf("default must mint 32 chars, got %q (%v)", id, ok)
	}
	size := 10
	id, ok = MintModelID(opts, "user", &size)
	if !ok || len(id) != 10 {
		t.Fatalf("size hint must flow to the minter, got %q (%v)", id, ok)
	}
	for _, n := range []int{0, -5} {
		id, ok = MintModelID(opts, "user", &n)
		if !ok || len(id) != 32 {
			t.Fatalf("non-positive size %d must fall back to 32, got %q (%v)", n, id, ok)
		}
	}
}

// TestMintModelID_CustomFunc ports the custom-function branch of upstream
func TestMintModelID_CustomFunc(t *testing.T) {
	var gotModel string
	var gotSize *int
	size := 24
	opts := Options{}
	opts.Advanced.Database.GenerateID.Func = func(model string, s *int) (string, bool) {
		gotModel = model
		gotSize = s
		return "custom-" + model, true
	}
	id, ok := MintModelID(opts, "session", &size)
	if !ok || id != "custom-session" {
		t.Fatalf("custom func must win, got %q (%v)", id, ok)
	}
	if gotModel != "session" {
		t.Fatalf("custom func must receive the model, got %q", gotModel)
	}
	if gotSize == nil || *gotSize != 24 {
		t.Fatalf("custom func must receive the size hint, got %v", gotSize)
	}
	if _, ok := MintModelID(opts, "user", nil); !ok {
		t.Fatal("custom func true must propagate")
	}
	if gotSize != nil {
		t.Fatalf("nil size hint must stay nil, got %v", *gotSize)
	}
	opts.Advanced.Database.GenerateID.Func = func(string, *int) (string, bool) {
		return "", false
	}
	if id, ok := MintModelID(opts, "user", nil); ok || id != "" {
		t.Fatalf("custom false must resolve to database-issued, got %q (%v)", id, ok)
	}
}

// TestMintModelID_UUIDMode ports the "uuid" shorthand: the minter returns a
// random UUID (upstream crypto.randomUUID).
func TestMintModelID_UUIDMode(t *testing.T) {
	var opts Options
	opts.Advanced.Database.GenerateID.Mode = GenerateIDModeUUID
	id, ok := MintModelID(opts, "user", nil)
	if !ok || len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Fatalf("uuid mode must mint a UUID, got %q (%v)", id, ok)
	}
	other, _ := MintModelID(opts, "user", nil)
	if other == id {
		t.Fatal("uuid mints must differ")
	}
}

// TestMintModelID_SerialMode ports the "serial"/false shorthand: the minter
// resolves to ("", false) so the database issues the ID (upstream
func TestMintModelID_SerialMode(t *testing.T) {
	var opts Options
	opts.Advanced.Database.GenerateID.Mode = GenerateIDModeSerial
	if id, ok := MintModelID(opts, "user", nil); ok || id != "" {
		t.Fatalf("serial mode must resolve to database-issued, got %q (%v)", id, ok)
	}
}
