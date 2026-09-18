package types

import (
	"context"
	"errors"
	"testing"
)

type collectPlugin struct {
	id        string
	endpoints []Endpoint
	named     map[string]Endpoint
	tsHooks   PluginTSRouteHooks
	overrides PluginAdapterOverrides
	migrates  map[string]PluginMigration
}

func (p collectPlugin) ID() string                    { return p.id }
func (p collectPlugin) Init(AuthContext) error        { return nil }
func (p collectPlugin) Endpoints() []Endpoint         { return p.endpoints }
func (p collectPlugin) Schema() PluginSchema          { return nil }
func (p collectPlugin) Hooks() DBHooks                { return nil }
func (p collectPlugin) RouteHooks() PluginRouteHooks  { return PluginRouteHooks{} }
func (p collectPlugin) ErrorCodes() map[string]string { return nil }
func (p collectPlugin) NamedEndpoints() map[string]Endpoint {
	return p.named
}
func (p collectPlugin) TSRouteHooks() PluginTSRouteHooks { return p.tsHooks }
func (p collectPlugin) AdapterOverrides() PluginAdapterOverrides {
	return p.overrides
}
func (p collectPlugin) Migrations() map[string]PluginMigration { return p.migrates }

func TestCollectPluginEndpointsMergesLegacyAndNamed(t *testing.T) {
	mk := func(op string) Endpoint { return Endpoint{OperationID: op} }
	plugins := []Plugin{
		collectPlugin{id: "a", endpoints: []Endpoint{mk("a-legacy")}, named: map[string]Endpoint{"z": mk("a-z"), "m": mk("a-m")}},
		collectPlugin{id: "b", endpoints: []Endpoint{mk("b-legacy")}},
	}
	got := CollectPluginEndpoints(plugins)
	want := []string{"a-legacy", "a-m", "a-z", "b-legacy"}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %v, want %v", got, want)
	}
	for i, op := range want {
		if got[i].OperationID != op {
			t.Fatalf("endpoints[%d] = %q, want %q (full %+v)", i, got[i].OperationID, op, got)
		}
	}
	// Legacy-only plugins keep working; nil plugins are skipped.
	if out := CollectPluginEndpoints([]Plugin{collectPlugin{id: "x"}}); len(out) != 0 {
		t.Fatalf("empty plugin must contribute no endpoints, got %+v", out)
	}
	if out := CollectPluginEndpoints(nil); len(out) != 0 {
		t.Fatalf("nil plugins must yield no endpoints, got %+v", out)
	}
}

func TestCollectTSRouteHooksConcatenates(t *testing.T) {
	ok := func(ctx PluginHookContext) error { return nil }
	plugins := []Plugin{
		collectPlugin{id: "a", tsHooks: PluginTSRouteHooks{Before: []PluginTSRouteBeforeHook{{Handler: ok}}}},
		collectPlugin{id: "b", tsHooks: PluginTSRouteHooks{After: []PluginTSRouteAfterHook{{Handler: ok}}}},
		collectPlugin{id: "c"},
	}
	got := CollectTSRouteHooks(plugins)
	if len(got.Before) != 1 || len(got.After) != 1 {
		t.Fatalf("must concatenate in declaration order, got %+v", got)
	}
}

func TestCollectAdapterOverridesLaterWins(t *testing.T) {
	a := PluginAdapterOverrideFunc(func(ctx context.Context, args ...any) (any, error) { return "a", nil })
	b := PluginAdapterOverrideFunc(func(ctx context.Context, args ...any) (any, error) { return "b", nil })
	got := CollectAdapterOverrides([]Plugin{
		collectPlugin{id: "a", overrides: PluginAdapterOverrides{"create": a}},
		collectPlugin{id: "b", overrides: PluginAdapterOverrides{"create": b, "delete": a}},
	})
	res, err := got["create"](context.Background())
	if err != nil || res != "b" {
		t.Fatalf("later plugin must win per operation, got (%v, %v)", res, err)
	}
	if _, ok := got["delete"]; !ok {
		t.Fatal("non-colliding operations must merge")
	}
}

func TestCollectPluginMigrationsAndRun(t *testing.T) {
	var order []string
	mk := func(name string) PluginMigration {
		return PluginMigration{Up: func(ctx context.Context) error {
			order = append(order, name)
			return nil
		}}
	}
	got := CollectPluginMigrations([]Plugin{
		collectPlugin{id: "a", migrates: map[string]PluginMigration{"002": mk("a-002"), "001": mk("a-001")}},
		collectPlugin{id: "b", migrates: map[string]PluginMigration{"003": mk("b-003")}},
	})
	if len(got) != 3 {
		t.Fatalf("must merge migrations, got %d", len(got))
	}
	if err := RunPluginMigrationsUp(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	// Deterministic sorted execution order.
	want := []string{"a-001", "a-002", "b-003"}
	if len(order) != len(want) {
		t.Fatalf("run order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("run order = %v, want %v", order, want)
		}
	}
}

func TestRunPluginMigrationsUpErrorWrapsName(t *testing.T) {
	boom := errors.New("up failed")
	migrations := map[string]PluginMigration{
		"001": {Up: func(ctx context.Context) error { return boom }},
		"002": {},
	}
	if err := RunPluginMigrationsUp(context.Background(), migrations); !errors.Is(err, boom) {
		t.Fatalf("migration error must propagate, got: %v", err)
	}
	// Nil Up is a documented no-op.
	if err := RunPluginMigrationsUp(context.Background(), map[string]PluginMigration{"x": {}}); err != nil {
		t.Fatalf("nil Up must be a no-op, got: %v", err)
	}
}
