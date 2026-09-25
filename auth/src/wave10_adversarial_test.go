package auth_test

// wave10_adversarial_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/danielgtaylor/huma/v2"
)

func boolPtrW10(b bool) *bool { return &b }

// Migration diffing under burst: concurrent DiffSchemas calls over fresh,
func TestWave10_DiffSchemasConcurrent(t *testing.T) {
	cfg := auth.AdapterConfig{}
	desired := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId":       {Type: auth.FieldTypeString},
			"connectionIssuer": {Type: auth.FieldTypeString, Required: boolPtrW10(true)},
		}},
	}
	current := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId": {Type: auth.FieldTypeString},
		}},
	}

	baseline, err := auth.DiffSchemas(current, desired, cfg, map[string]bool{"directory_users": true}, false)
	if err != nil {
		t.Fatalf("baseline diff: %v", err)
	}
	if len(baseline.ToBeAdded) != 1 || len(baseline.UnsafeChanges) != 1 {
		t.Fatalf("baseline shape wrong: %+v", baseline)
	}

	const racers = 16
	var wg sync.WaitGroup
	errs := make(chan string, racers*3)
	run := func(populated map[string]bool, wantAdded, wantUnsafe int) {
		defer wg.Done()
		got, err := auth.DiffSchemas(current, desired, cfg, populated, false)
		if err != nil {
			errs <- fmt.Sprintf("diff error: %v", err)
			return
		}
		if len(got.ToBeAdded) != wantAdded || len(got.UnsafeChanges) != wantUnsafe {
			errs <- fmt.Sprintf("diff shape = +%d ~%d, want +%d ~%d",
				len(got.ToBeAdded), len(got.UnsafeChanges), wantAdded, wantUnsafe)
			return
		}
		if !reflect.DeepEqual(got, baseline) && populated != nil {
			errs <- "populated diff not DeepEqual to baseline"
		}
	}
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go run(map[string]bool{"directory_users": true}, 1, 1)
	}
	freshBaseline, err := auth.DiffSchemas(auth.PluginSchema{}, desired, cfg, nil, false)
	if err != nil {
		t.Fatalf("fresh baseline: %v", err)
	}
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := auth.DiffSchemas(auth.PluginSchema{}, desired, cfg, nil, false)
			if err != nil {
				errs <- fmt.Sprintf("fresh diff error: %v", err)
				return
			}
			if !reflect.DeepEqual(got, freshBaseline) {
				errs <- "fresh diff not DeepEqual to baseline"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// Hook ordering under concurrency: 16 simultaneous requests each carrying a
func TestWave10_HookOrderUnderConcurrency(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	record := func(tag, id string) {
		mu.Lock()
		defer mu.Unlock()
		seen[tag] = append(seen[tag], id)
	}
	mkPlugin := func(id string) *routeHookPlugin {
		return &routeHookPlugin{
			id: id,
			before: []auth.PluginRouteBeforeHook{
				{
					Matcher: func(ctx huma.Context) bool {
						return strings.HasSuffix(ctx.Operation().Path, "/ok")
					},
					Handler: func(ctx huma.Context) (huma.Context, error) {
						record(ctx.Header("X-W10-Req"), id)
						return nil, nil
					},
				},
			},
			after: []auth.PluginRouteAfterHook{
				{
					Matcher: func(ctx huma.Context) bool {
						return strings.HasSuffix(ctx.Operation().Path, "/ok")
					},
					Handler: func(ctx huma.Context) {
						record(ctx.Header("X-W10-Req"), id+"-after")
					},
				},
			},
		}
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{mkPlugin("p1"), mkPlugin("p2")},
	})
	defer srv.Close()

	const racers = 16
	var wg sync.WaitGroup
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest("GET", srv.URL+"/api/auth/ok", nil)
			if err != nil {
				return
			}
			req.Header.Set("X-W10-Req", fmt.Sprintf("req-%d", i))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != racers {
		t.Fatalf("hook tags seen = %d, want %d (%v)", len(seen), racers, seen)
	}
	for tag, order := range seen {
		want := []string{"p1", "p2", "p1-after", "p2-after"}
		if !reflect.DeepEqual(order, want) {
			t.Errorf("request %s hook order = %v, want %v", tag, order, want)
		}
	}
}
