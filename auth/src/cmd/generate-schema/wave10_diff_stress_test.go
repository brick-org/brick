package main

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).

import (
	"encoding/json"
	"sync"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// Migration planning under burst: concurrent BuildMigrationPlan calls return byte-identical scripts.
func TestWave10_MigrationPlanBurstDeterministic(t *testing.T) {
	schema := testSchema()
	cfg := testConfig()
	dialects := []Dialect{DialectSQLite, DialectPostgres, DialectMySQL, DialectMSSQL}

	baseline := map[Dialect]string{}
	for _, d := range dialects {
		plan, err := BuildMigrationPlan(schema, cfg, d, "string")
		if err != nil {
			t.Fatalf("[%s] baseline: %v", d, err)
		}
		if plan.Script() == "" {
			t.Fatalf("[%s] baseline script must not be empty", d)
		}
		baseline[d] = plan.Script()
	}

	const racers = 8
	var wg sync.WaitGroup
	errs := make(chan string, racers*len(dialects))
	for _, d := range dialects {
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(d Dialect) {
				defer wg.Done()
				plan, err := BuildMigrationPlan(schema, cfg, d, "string")
				if err != nil {
					errs <- "plan error under burst"
					return
				}
				if plan.Script() != baseline[d] {
					errs <- "nondeterministic migration script under burst"
				}
			}(d)
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// FuzzWave10_SchemaPlanJSON fuzzes hostile schema documents through the plan builder.
func FuzzWave10_SchemaPlanJSON(f *testing.F) {
	f.Add(`{"user":{"fields":{"name":{"type":"string"}}}}`)
	f.Add(`{}`)
	f.Add(`{"t; DROP TABLE x;--":{"fields":{"a;b":{"type":"string"}}}}`)
	f.Add(`{"user":{"fields":{"u":{"type":"string","unique":true},"v":{"type":"string","unique":true}},"indexes":[{"fields":["u","v"],"name":"x","unique":true}]}}`)
	f.Fuzz(func(t *testing.T, doc string) {
		if len(doc) > 4096 {
			t.Skip("over wave10 4KiB cap")
		}
		var schema auth.PluginSchema
		if err := json.Unmarshal([]byte(doc), &schema); err != nil {
			return
		}
		for _, d := range []Dialect{DialectSQLite, DialectPostgres} {
			first, err1 := BuildMigrationPlan(schema, testConfig(), d, "string")
			second, err2 := BuildMigrationPlan(schema, testConfig(), d, "string")
			if (err1 == nil) != (err2 == nil) {
				t.Fatalf("[%s] nondeterministic plan error for %q", d, doc)
			}
			if err1 != nil {
				continue
			}
			if first.Script() != second.Script() {
				t.Fatalf("[%s] nondeterministic script for %q", d, doc)
			}
		}
	})
}
