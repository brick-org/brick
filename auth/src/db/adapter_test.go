package db

import (
	"strings"
	"testing"
)

func TestDefaultCapabilities_MatchFactoryDefaults(t *testing.T) {
	caps := DefaultCapabilities()
	if !caps.SupportsDates || !caps.SupportsBooleans || !caps.SupportsNumericIDs {
		t.Fatalf("dates/booleans/numeric IDs default true upstream: %+v", caps)
	}
	if caps.SupportsJSON || caps.SupportsArrays || caps.SupportsUUIDs || caps.UsePlural {
		t.Fatalf("JSON/arrays/UUIDs/plural default false upstream: %+v", caps)
	}
}

func TestValidateIdentifier(t *testing.T) {
	valid := []string{"users", "email_address", "_private", "auth.users", "a.b", "T1", "x9_"}
	for _, name := range valid {
		if err := ValidateIdentifier(name); err != nil {
			t.Fatalf("ValidateIdentifier(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"", ".", "a.", ".a", "a.b.c", "user; DROP TABLE users",
		"a b", "a-b", `"quoted"`, "a'b", "a$b", "0abc", "table--x",
		"users/*", "users(id)",
	}
	for _, name := range invalid {
		err := ValidateIdentifier(name)
		if err == nil {
			t.Fatalf("ValidateIdentifier(%q) = nil, want error", name)
		}
		if _, ok := err.(*InvalidIdentifierError); !ok {
			t.Fatalf("ValidateIdentifier(%q) error type %T, want *InvalidIdentifierError", name, err)
		}
	}
}

func TestJoinLimit_DefaultAndOverride(t *testing.T) {
	var unset JoinModelOption
	if got := unset.JoinLimit(); got != DefaultFindManyLimit {
		t.Fatalf("default join limit = %d, want %d", got, DefaultFindManyLimit)
	}
	n := 7
	set := JoinModelOption{Limit: &n}
	if got := set.JoinLimit(); got != 7 {
		t.Fatalf("override join limit = %d, want 7", got)
	}
}

func TestJoinRelation_Validity(t *testing.T) {
	if !JoinOneToOne.IsValid() || !JoinOneToMany.IsValid() {
		t.Fatal("one-to-one/one-to-many must be valid")
	}
	if JoinRelation("many-to-many").IsValid() || JoinRelation("").IsValid() {
		t.Fatal("many-to-many/empty must not be valid relations")
	}
}

func TestValidationErrors_Format(t *testing.T) {
	if got := (&InvalidModelError{Model: "user"}).Error(); !strings.Contains(got, `"user"`) {
		t.Fatalf("InvalidModelError names the model: %q", got)
	}
	if got := (&InvalidFieldError{Model: "user", Field: "nope"}).Error(); !strings.Contains(got, `"nope"`) || !strings.Contains(got, `"user"`) {
		t.Fatalf("InvalidFieldError names field and model: %q", got)
	}
	if got := (&InvalidValueError{Model: "user", Field: "age", Reason: "boom"}).Error(); !strings.Contains(got, "boom") {
		t.Fatalf("InvalidValueError carries the reason: %q", got)
	}
	if got := (&InvalidIdentifierError{Name: "a b", Kind: "column"}).Error(); !strings.Contains(got, "column") {
		t.Fatalf("InvalidIdentifierError names the kind: %q", got)
	}
}

func TestNormalizeHelpers_DocumentBehavior(t *testing.T) {
	if NormalizeConnector("OR") != Connector(ConnectorOR) || NormalizeConnector("") != Connector(ConnectorAND) {
		t.Fatal("connector normalization must map OR/empty")
	}
	if NormalizeWhereMode("insensitive") != WhereModeInsensitiveKind || NormalizeWhereMode("bogus") != WhereModeSensitiveKind {
		t.Fatal("where-mode normalization must map insensitive/garbage")
	}
	if NormalizeSortDirection("desc") != SortDirection(SortDirectionDesc) || NormalizeSortDirection("") != SortDirection(SortDirectionAsc) {
		t.Fatal("sort-direction normalization must map desc/empty")
	}
}
