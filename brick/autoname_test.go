package brick

import (
	"context"
	"strings"
	"testing"

	"github.com/brick-org/brick/dsl/schema"
)

func TestNewUUIDShape(t *testing.T) {
	a, b := newUUID(), newUUID()
	if a == b {
		t.Error("UUIDs must differ")
	}
	for _, u := range []string{a, b} {
		if len(u) != 36 {
			t.Errorf("UUID length: %q", u)
		}
		parts := strings.Split(u, "-")
		if len(parts) != 5 {
			t.Errorf("UUID dashes: %q", u)
		}
		if parts[2][0] != '4' {
			t.Errorf("UUID version nibble: %q", u)
		}
	}
}

func TestRandBase36(t *testing.T) {
	s := randBase36(10)
	if len(s) != 10 {
		t.Fatalf("length: %q", s)
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			t.Fatalf("charset: %q", s)
		}
	}
	if randBase36(0) == "" {
		t.Error("non-positive length must default")
	}
}

func TestApplyAutonamePrompt(t *testing.T) {
	pk := &schema.PK{Column: "name", Autoname: AutonamePrompt()}
	body := map[string]any{}
	if err := applyAutoname(context.Background(), nil, "t", pk, body); err == nil {
		t.Error("missing prompt PK must 422")
	}
	body["name"] = "client-value"
	if err := applyAutoname(context.Background(), nil, "t", pk, body); err != nil {
		t.Errorf("supplied prompt PK: %v", err)
	}
}

func TestApplyAutonameUUIDFill(t *testing.T) {
	pk := UUIDPK("id")
	body := map[string]any{}
	if err := applyAutoname(context.Background(), nil, "t", pk, body); err != nil {
		t.Fatalf("uuid: %v", err)
	}
	if _, ok := body["id"].(string); !ok || body["id"] == "" {
		t.Errorf("uuid not filled: %+v", body)
	}
	// Pre-set value survives.
	body["id"] = "keep"
	if err := applyAutoname(context.Background(), nil, "t", pk, body); err != nil || body["id"] != "keep" {
		t.Errorf("preset uuid overwritten: %+v (%v)", body, err)
	}
}

func TestPKConstructors(t *testing.T) {
	if p := AutoincPK("name"); p.Column != "name" || p.Autoname.Strategy != schema.AutonameAutoinc {
		t.Errorf("AutoincPK: %+v", p)
	}
	if a := AutonameHash(10); a.Strategy != schema.AutonameHash || a.HashLen != 10 {
		t.Errorf("AutonameHash: %+v", a)
	}
}
