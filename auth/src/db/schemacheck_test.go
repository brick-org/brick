package db

import (
	"errors"
	"sync"
	"testing"
)

// Port of vendor/.../core/src/db/schema-check.test.ts (Better Auth v1.7.5,
// commit 5468e6bf): createSchemaCheck caching/invalidation, checksSchema gate,
// and the adapter→check registry.

func TestSchemaCheck_InvalidatesOnlyMigratedDatabase(t *testing.T) {
	database := struct{ id int }{id: 1}
	other := struct{ id int }{id: 2}
	calls, otherCalls := 0, 0
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		return nil, nil
	}, SchemaSourceDatabase, &database)
	otherCheck := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		otherCalls++
		return nil, nil
	}, SchemaSourceDatabase, &other)
	if err := awaitCheck(check()); err != nil {
		t.Fatal(err)
	}
	if err := awaitCheck(otherCheck()); err != nil {
		t.Fatal(err)
	}
	InvalidateSchemaChecks(&database)
	if err := awaitCheck(check()); err != nil {
		t.Fatal(err)
	}
	if err := awaitCheck(otherCheck()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || otherCalls != 1 {
		t.Fatalf("calls = %d, other = %d; want 2, 1", calls, otherCalls)
	}
}

func TestSchemaCheck_AsksOnceThenAnswersWithoutPromise(t *testing.T) {
	calls := 0
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		return nil, nil
	}, SchemaSourceDatabase)
	if err := awaitCheck(check()); err != nil {
		t.Fatal(err)
	}
	if done, err := checkSync(check); err != nil || !done {
		t.Fatalf("second check must be clean without a promise: done=%v err=%v", done, err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestSchemaCheck_SharesOneLookupBetweenConcurrentFirstCalls(t *testing.T) {
	calls := 0
	release := make(chan struct{})
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		<-release
		return nil, nil
	}, SchemaSourceDatabase)
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = awaitCheck(check())
		}(i)
	}
	close(release)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("concurrent first calls must share one lookup, got %d", calls)
	}
}

func TestSchemaCheck_KeepsOneMismatchAndRethrowsWithoutAskingAgain(t *testing.T) {
	calls := 0
	drift := SchemaFinding{Kind: "unexpected-required-column", Table: "account", Column: "issuer"}
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		return []SchemaFinding{drift}, nil
	}, SchemaSourceDatabase)
	first := awaitCheckErr(check())
	second := awaitCheckErr(check())
	var firstMismatch, secondMismatch *SchemaMismatchError
	if !errors.As(first, &firstMismatch) || !errors.As(second, &secondMismatch) {
		t.Fatalf("both must be SchemaMismatchError: %v %v", first, second)
	}
	if calls != 1 {
		t.Fatalf("mismatch must be asked once, got %d", calls)
	}
}

func TestSchemaCheck_AsksAgainAfterStoreUnreachable(t *testing.T) {
	calls := 0
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("ECONNREFUSED")
		}
		return nil, nil
	}, SchemaSourceDatabase)
	if err := awaitCheck(check()); err == nil {
		t.Fatal("first must fail")
	}
	if err := awaitCheck(check()); err != nil {
		t.Fatalf("second must succeed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestSchemaCheck_TurnsSyncFailureIntoRetryableRejection(t *testing.T) {
	failure := errors.New("connection unavailable")
	calls := 0
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) {
		calls++
		if calls == 1 {
			panic(failure)
		}
		return nil, nil
	}, SchemaSourceDatabase)
	if err := awaitCheck(check()); !errors.Is(err, failure) {
		t.Fatalf("sync panic must surface: %v", err)
	}
	if err := awaitCheck(check()); err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
}

func TestChecksSchema_DefaultEnabledUnlessDisabled(t *testing.T) {
	if !ChecksSchema(nil) {
		t.Fatal("nil must check (upstream default true)")
	}
	f := false
	if ChecksSchema(&f) {
		t.Fatal("explicit false must skip")
	}
	tr := true
	if !ChecksSchema(&tr) {
		t.Fatal("explicit true must check")
	}
}

func TestSchemaCheckRegistry_FindsRegisteredCheck(t *testing.T) {
	adapter := &struct{}{}
	check := CreateSchemaCheck(func() ([]SchemaFinding, error) { return nil, nil }, SchemaSourceDatabase)
	RegisterSchemaCheck(adapter, check)
	if SchemaCheckFor(adapter) == nil {
		t.Fatal("must find registered check")
	}
	if SchemaCheckFor(&struct{}{}) != nil {
		t.Fatal("must find nothing for others")
	}
}

func awaitCheck(p <-chan error) error {
	if p == nil {
		return nil
	}
	return <-p
}

func awaitCheckErr(p <-chan error) error {
	if p == nil {
		return nil
	}
	return <-p
}

func checkSync(check SchemaCheck) (bool, error) {
	p := check()
	if p != nil {
		return false, awaitCheck(p)
	}
	return true, nil
}
