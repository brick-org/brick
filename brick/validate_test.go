package brick

import (
	"context"
	"testing"

	"github.com/brick-org/brick/dsl/schema"
)

func testSchema() *schema.DynamicSchema {
	return &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":      schema.String().Readonly(),
			"team":    schema.String().Required().Filterable(),
			"owner":   schema.String().From("session.userId"),
			"slug":    schema.String().Required().Unique(),
			"title":   schema.String().Required().Searchable().MaxLen(6),
			"kind":    schema.Enum("a", "b").Default("a"),
			"note":    schema.Text(),
			"secret":  schema.String().Hidden(),
			"ro":      schema.String().Readonly(),
			"created": schema.String().Readonly(),
		},
		HiddenFields: []string{"secret"},
	}
}

func testResource() ResourceConfig {
	return ResourceConfig{Name: "widget", Table: "widgets", Schema: testSchema()}
}

func TestStripUnknownKeys(t *testing.T) {
	r := testResource()
	body := map[string]any{"team": "t", "slug": "s", "attacker": 1}
	stripUnknownKeys(r, body)
	if _, ok := body["attacker"]; ok {
		t.Error("unknown key survived strip")
	}
	if body["team"] != "t" {
		t.Error("known key was stripped")
	}
}

func TestApplyFromSourcesOverwrites(t *testing.T) {
	r := testResource()
	ctx := storeAppCtx(context.Background(), &AppCtx{
		Actor:   &User{ID: "ada"},
		Session: &Session{ID: "s", UserID: "ada"},
	})
	body := map[string]any{"owner": "mallory"}
	if err := applyFromSources(ctx, r, body); err != nil {
		t.Fatalf("from: %v", err)
	}
	if body["owner"] != "ada" {
		t.Errorf("from: must overwrite client value, got %v", body["owner"])
	}

	// Anonymous with non-optional from: → 401.
	if err := applyFromSources(context.Background(), r, map[string]any{}); err == nil {
		t.Error("anonymous from: must 401")
	}
}

func TestValidateCreateBody(t *testing.T) {
	r := testResource()

	// Missing required team/slug/title → 422.
	if err := validateCreateBody(r, map[string]any{"team": "t"}); err == nil {
		t.Error("missing required must 422")
	} else if se, ok := err.(interface{ GetStatus() int }); !ok || se.GetStatus() != 422 {
		t.Errorf("must be 422, got %T %v", err, err)
	}

	// Blank string fails required.
	if err := validateCreateBody(r, map[string]any{"team": "t", "slug": "  ", "title": "x"}); err == nil {
		t.Error("blank required must 422")
	}

	// Over maxlen (title max 6 runes).
	if err := validateCreateBody(r, map[string]any{"team": "t", "slug": "s", "title": "way-too-long"}); err == nil {
		t.Error("over-maxlen must 422")
	}

	// Bad enum.
	if err := validateCreateBody(r, map[string]any{"team": "t", "slug": "s", "title": "ok", "kind": "zzz"}); err == nil {
		t.Error("bad enum must 422")
	}

	// Valid body passes (unknown/defaults handled elsewhere).
	if err := validateCreateBody(r, map[string]any{"team": "t", "slug": "s", "title": "ok", "kind": "b"}); err != nil {
		t.Errorf("valid body: %v", err)
	}
}

func TestValidateUpdateBodyPartial(t *testing.T) {
	r := testResource()
	// Required NOT enforced on update; only present fields checked.
	if err := validateUpdateBody(r, map[string]any{"title": "ok"}); err != nil {
		t.Errorf("partial update: %v", err)
	}
	if err := validateUpdateBody(r, map[string]any{"title": "way-too-long"}); err == nil {
		t.Error("over-maxlen on update must 422")
	}
	if err := validateUpdateBody(r, map[string]any{"kind": "zzz"}); err == nil {
		t.Error("bad enum on update must 422")
	}
}

func TestValidationCollector(t *testing.T) {
	var v Validation
	if v.Errs() != nil {
		t.Error("empty collector must return nil")
	}
	v.Required("name", "x")
	v.Required("missing", nil)
	v.Required("blank", "  ")
	v.Email("e1", "")
	v.Email("e2", "good@example.com")
	v.Email("e3", "not-an-email")
	v.Domain("d1", "")
	v.Domain("d2", "example.com")
	v.Domain("d3", "no dot")
	v.Range("p", 50, 0, 100)
	v.Range("q", 101, 0, 100)
	v.Add("c", "custom", "custom message")
	errs := v.Errs()
	if len(errs) != 6 {
		t.Fatalf("expected 6 failures, got %+v", errs)
	}

	uerr := Unprocessable(errs)
	if uerr.GetStatus() != 422 {
		t.Errorf("Unprocessable must be 422, got %d", uerr.GetStatus())
	}
	if c := Conflict("dup"); c.GetStatus() != 409 {
		t.Errorf("Conflict must be 409, got %d", c.GetStatus())
	}
}
