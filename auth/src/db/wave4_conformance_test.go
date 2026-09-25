package db

// Wave 4 conformance: adapter-vocabulary parity, fuzz targets, race tests, malformed-input limits.

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Upstream whereOperators 1:1 vocabulary.
func TestWave4_OperatorVocabulary(t *testing.T) {
	upstream := []Operator{
		"eq", "ne", "lt", "lte", "gt", "gte",
		"in", "not_in", "contains", "starts_with", "ends_with",
	}
	ported := []Operator{
		OpEq, OpNe, OpLt, OpLte, OpGt, OpGte,
		OpIn, OpNotIn, OpContains, OpStartsWith, OpEndsWith,
	}
	if len(ported) != len(upstream) {
		t.Fatalf("vocabulary size = %d, want %d", len(ported), len(upstream))
	}
	for i := range upstream {
		if ported[i] != upstream[i] {
			t.Errorf("operator[%d] = %q, want %q", i, ported[i], upstream[i])
		}
	}
	aliases := map[Operator]Operator{
		Eq: OpEq, Ne: OpNe, Lt: OpLt, Lte: OpLte, Gt: OpGt, Gte: OpGte,
		In: OpIn, NotIn: OpNotIn, Contains: OpContains,
		StartsWith: OpStartsWith, EndsWith: OpEndsWith,
	}
	for alias, full := range aliases {
		if alias != full {
			t.Errorf("alias %q != %q", alias, full)
		}
	}
	if DefaultFindManyLimit != 100 {
		t.Errorf("DefaultFindManyLimit = %d, want 100 (upstream default)", DefaultFindManyLimit)
	}
}

// Upstream normalization: unknown/empty connector/mode/direction values silently take defaults.
func TestWave4_NormalizeMatrix(t *testing.T) {
	for _, s := range []string{"OR", "or", "Or", " oR "} {
		_ = s
	}
	if NormalizeConnector("OR") != ConnectorOR || NormalizeConnector("or") != ConnectorOR {
		t.Error("OR must normalize to OR")
	}
	for _, s := range []string{"", "AND", "and", "XOR", "OR OR", "o r", "null"} {
		if NormalizeConnector(s) != ConnectorAND {
			t.Errorf("connector %q must normalize to AND", s)
		}
	}
	if NormalizeWhereMode("insensitive") != WhereModeInsensitiveKind || NormalizeWhereMode("INSENSITIVE") != WhereModeInsensitiveKind {
		t.Error("insensitive must normalize to insensitive")
	}
	for _, s := range []string{"", "sensitive", "SENSITIVE", "binary", "ci"} {
		if NormalizeWhereMode(s) != WhereModeSensitiveKind {
			t.Errorf("mode %q must normalize to sensitive", s)
		}
	}
	if NormalizeSortDirection("desc") != SortDirectionDesc || NormalizeSortDirection("DESC") != SortDirectionDesc {
		t.Error("desc must normalize to desc")
	}
	for _, s := range []string{"", "asc", "ASC", "ascending", "1", "-1"} {
		if NormalizeSortDirection(s) != SortDirectionAsc {
			t.Errorf("direction %q must normalize to asc", s)
		}
	}
	if !Connector(ConnectorOR).IsValid() || !Connector("and").IsValid() || Connector("").IsValid() || Connector("XOR").IsValid() {
		t.Error("Connector.IsValid matrix wrong")
	}
	if !WhereMode(WhereModeSensitive).IsValid() || !WhereMode("INSENSITIVE").IsValid() || WhereMode("").IsValid() {
		t.Error("WhereMode.IsValid matrix wrong")
	}
	if !SortDirection(SortDirectionAsc).IsValid() || !SortDirection("DESC").IsValid() || SortDirection("").IsValid() {
		t.Error("SortDirection.IsValid matrix wrong")
	}
}

// Identifier trust boundary: optional single schema qualifier, strict charset; hostile inputs rejected.
func TestWave4_ValidateIdentifierMatrix(t *testing.T) {
	valid := []string{"a", "_x", "abc123", "sch.tab", "_._", "A_Z_09"}
	for _, name := range valid {
		if err := ValidateIdentifier(name); err != nil {
			t.Errorf("ValidateIdentifier(%q) must pass: %v", name, err)
		}
	}
	invalid := []string{
		"", "0a", "a b", "a-b", "a\"b", "a'b", "a;b", "a.b.c", ".a", "a.",
		"sch..tab", "a\nb", "a\x00b", "ünïcode", "tab; DROP TABLE x;--",
		strings.Repeat("x", 1<<20) + "!", `"quoted"`,
	}
	for _, name := range invalid {
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) must reject", name)
		}
	}
}

func TestWave4_JoinOptionGolden(t *testing.T) {
	var unset JoinModelOption
	if unset.JoinLimit() != DefaultFindManyLimit {
		t.Errorf("default join limit = %d", unset.JoinLimit())
	}
	n := 5
	set := JoinModelOption{Limit: &n}
	if set.JoinLimit() != 5 {
		t.Errorf("join limit override = %d", set.JoinLimit())
	}
	zero := 0
	if (JoinModelOption{Limit: &zero}).JoinLimit() != 0 {
		t.Error("explicit zero join limit must hold")
	}
	if !JoinOneToOne.IsValid() || !JoinOneToMany.IsValid() || JoinRelation("many-to-many").IsValid() {
		t.Error("JoinRelation validity matrix wrong (upstream factory only emits one-to-one/one-to-many)")
	}
}

func TestWave4_DBContractLimits(t *testing.T) {
	huge := strings.Repeat("O", 1<<20)
	if NormalizeConnector(huge) != ConnectorAND {
		t.Error("1MB connector must normalize to AND")
	}
	if NormalizeWhereMode(huge) != WhereModeSensitiveKind {
		t.Error("1MB mode must normalize to sensitive")
	}
	if NormalizeSortDirection(huge) != SortDirectionAsc {
		t.Error("1MB direction must normalize to asc")
	}
	if err := ValidateIdentifier(huge + "!"); err == nil {
		t.Error("1MB hostile identifier must reject")
	}
	if err := ValidateIdentifier(huge); err != nil {
		t.Errorf("1MB clean identifier must pass: %v", err)
	}
	cfg := Config{}
	if cfg.ModelName("user") != "user" || cfg.FieldName("user", "email") != "email" {
		t.Error("empty config must pass through")
	}
}

func TestWave4_DBContractConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = NormalizeConnector("OR")
				_ = NormalizeWhereMode("insensitive")
				_ = NormalizeSortDirection("desc")
				_ = ValidateIdentifier("sch.tab")
				_ = DefaultCapabilities()
				_ = (JoinModelOption{}).JoinLimit()
			}
		}()
	}
	wg.Wait()
}

var wave4IdentPart = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func referenceValidateIdentifier(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if !wave4IdentPart.MatchString(p) {
			return false
		}
	}
	return true
}

func FuzzValidateIdentifier(f *testing.F) {
	for _, s := range []string{
		"", "a", "abc123", "_x", "sch.tab", "a.b.c", "0a", "a b",
		"a\" OR \"1\"=\"1", "tab; DROP TABLE x;--", "ünïcode", ".a", "a.",
		`"quoted"`, "A_Z_09",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := ValidateIdentifier(name)
		if want := referenceValidateIdentifier(name); (got == nil) != want {
			t.Fatalf("ValidateIdentifier(%q) = %v, oracle = %v", name, got, want)
		}
	})
}

func FuzzNormalizeHelpers(f *testing.F) {
	for _, s := range []string{"", "AND", "OR", "or", "sensitive", "insensitive", "asc", "desc", "DESC", "bogus"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c := NormalizeConnector(s)
		if c != ConnectorAND && c != ConnectorOR {
			t.Fatalf("connector out of vocabulary: %q", c)
		}
		m := NormalizeWhereMode(s)
		if m != WhereModeSensitiveKind && m != WhereModeInsensitiveKind {
			t.Fatalf("mode out of vocabulary: %q", m)
		}
		d := NormalizeSortDirection(s)
		if d != SortDirectionAsc && d != SortDirectionDesc {
			t.Fatalf("direction out of vocabulary: %q", d)
		}
		if strings.EqualFold(s, "OR") && c != ConnectorOR {
			t.Fatalf("case-insensitive OR failed for %q", s)
		}
		if strings.EqualFold(s, "insensitive") && m != WhereModeInsensitiveKind {
			t.Fatalf("case-insensitive insensitive failed for %q", s)
		}
		if strings.EqualFold(s, "desc") && d != SortDirectionDesc {
			t.Fatalf("case-insensitive desc failed for %q", s)
		}
	})
}
