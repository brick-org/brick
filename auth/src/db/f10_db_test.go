package db

// F10 (PARITY_V3 gap 14 core subset): reserveVerificationValue, typed
// duplicate-key errors, and ConsumeOne-with-fallback for the verification
// consume paths. Tests-first: this file FAILS pre-fix (symbols do not exist
// yet) and gates the implementation in adapter-base.go / with-hooks.go.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestF10_VerificationReservationID_Deterministic(t *testing.T) {
	// Upstream: base64url-nopad(SHA-256("reserve:" + identifier))
	// (internal-adapter.ts reserveVerificationValue). Vector computed from
	// the pinned algorithm: SHA-256 over UTF-8 bytes, unpadded base64url.
	const want = "BPk08ihEN5h8SOKGkEOM1LNCordg96ZsMmdCyzdqND4"
	if got := VerificationReservationID("reserve:once"); got != want {
		t.Fatalf("VerificationReservationID(reserve:once) = %q, want %q", got, want)
	}
	if got := VerificationReservationID("reserve:once"); got != want {
		t.Fatalf("reservation ID must be deterministic, got %q", got)
	}
	other := VerificationReservationID("reserve:other")
	if other == want {
		t.Fatal("distinct identifiers must yield distinct reservation IDs")
	}
	if strings.ContainsAny(VerificationReservationID("x"), "+/=") {
		t.Fatal("reservation ID must be unpadded base64url (no +/=)")
	}
	if n := len(VerificationReservationID("x")); n != 43 {
		t.Fatalf("32-byte hash encodes to 43 unpadded chars, got %d", n)
	}
}

func TestF10_DuplicateKeyError_Mapping(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"pg-code", `ERROR: duplicate key value violates unique constraint "u" (SQLSTATE 23505)`, true},
		{"pg-text", `pq: duplicate key value violates unique constraint "users_email_key"`, true},
		{"sqlite-code", `constraint failed: UNIQUE constraint failed: users.email (1555) (SQLITE_CONSTRAINT_UNIQUE)`, true},
		{"sqlite-pk", `constraint failed: PRIMARY KEY constraint failed: verifications (SQLITE_CONSTRAINT_PRIMARYKEY)`, true},
		{"mysql-code", `Error 1062 (23000): Duplicate entry 'a@b.c' for key 'users.email'`, true},
		{"mysql-text", `mysql: Duplicate entry '1' for key 'PRIMARY'`, true},
		{"mssql-unique-index", `Violation of UNIQUE KEY constraint 'UQ__users'. Cannot insert duplicate key in object 'dbo.users'. (2601)`, true},
		{"mssql-pk", `Violation of PRIMARY KEY constraint 'PK__users'. Cannot insert duplicate key in object 'dbo.users'. (2627)`, true},
		{"unrelated", `connection refused`, false},
		{"syntax", `syntax error at or near "FROM"`, false},
		{"count-mention", `rows affected: 3`, false},
	}
	for _, tc := range cases {
		err := MapDuplicateKeyError("user", errors.New(tc.msg))
		if got := IsDuplicateKeyError(err); got != tc.want {
			t.Fatalf("%s: IsDuplicateKeyError = %v, want %v (err=%v)", tc.name, got, tc.want, err)
		}
		if tc.want {
			var dup *DuplicateKeyError
			if !errors.As(err, &dup) {
				t.Fatalf("%s: mapped error must be *DuplicateKeyError, got %T", tc.name, err)
			}
			if dup.Model != "user" {
				t.Fatalf("%s: DuplicateKeyError.Model = %q, want %q", tc.name, dup.Model, "user")
			}
		}
	}
	if err := MapDuplicateKeyError("user", nil); err != nil {
		t.Fatalf("mapping nil must stay nil, got %v", err)
	}
	if err := MapDuplicateKeyError("user", context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("non-duplicate errors must pass through unchanged, got %v", err)
	}
	var dup *DuplicateKeyError
	if !errors.As(fmt.Errorf("bun Create user: %w", &DuplicateKeyError{Model: "user"}), &dup) {
		t.Fatal("DuplicateKeyError must survive %w wrapping (adapter layer wraps)")
	}
}

// f10FakeAdapter is a minimal in-memory Adapter for reserve/consume tests.
// Create enforces primary-key uniqueness with a sqlite-flavored duplicate
// error so the portable re-read path is exercised without a live database.
type f10FakeAdapter struct {
	mu                 sync.Mutex
	rows               map[string]map[string]any
	consumeUnsupported bool
	consumeErr         error
	createErr          error
	deletedWhere       [][]Where
	consumeCalls       int
}

func newF10FakeAdapter() *f10FakeAdapter {
	return &f10FakeAdapter{rows: map[string]map[string]any{}}
}

func (m *f10FakeAdapter) Create(_ context.Context, _ string, data map[string]any, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return nil, m.createErr
	}
	id, _ := data["id"].(string)
	if id == "" {
		return nil, errors.New("f10 fake: missing id")
	}
	if _, ok := m.rows[id]; ok {
		return nil, errors.New("constraint failed: UNIQUE constraint failed: verifications.id (SQLITE_CONSTRAINT_UNIQUE)")
	}
	cp := map[string]any{}
	for k, v := range data {
		cp[k] = v
	}
	m.rows[id] = cp
	return cp, nil
}

func eqID(id any) []Where { return []Where{{Field: "id", Value: id}} }

func (m *f10FakeAdapter) FindOne(_ context.Context, _ string, where []Where, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
rows:
	for _, row := range m.rows {
		for _, w := range where {
			if w.Operator != "" && w.Operator != OpEq {
				continue rows
			}
			v, ok := row[w.Field]
			if !ok {
				continue rows
			}
			if fmt.Sprintf("%v", v) != fmt.Sprintf("%v", w.Value) {
				continue rows
			}
		}
		cp := map[string]any{}
		for k, v := range row {
			cp[k] = v
		}
		return cp, nil
	}
	return nil, nil
}

func (m *f10FakeAdapter) FindMany(_ context.Context, _ string, _ []Where, _, _ int, _ *SortBy, _ []string) ([]map[string]any, error) {
	return nil, nil
}

func (m *f10FakeAdapter) Count(_ context.Context, _ string, _ []Where) (int, error) {
	return 0, nil
}

func (m *f10FakeAdapter) Update(_ context.Context, _ string, _ []Where, _ map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *f10FakeAdapter) UpdateMany(_ context.Context, _ string, _ []Where, _ map[string]any) (int, error) {
	return 0, nil
}

func (m *f10FakeAdapter) Delete(_ context.Context, _ string, where []Where) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedWhere = append(m.deletedWhere, where)
	for _, w := range where {
		if w.Field == "id" {
			if id, ok := w.Value.(string); ok {
				delete(m.rows, id)
			}
		}
	}
	return nil
}

func (m *f10FakeAdapter) DeleteMany(_ context.Context, _ string, _ []Where) (int, error) {
	return 0, nil
}

func (m *f10FakeAdapter) ConsumeOne(_ context.Context, _ string, where []Where) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consumeCalls++
	if m.consumeErr != nil {
		return nil, m.consumeErr
	}
	if m.consumeUnsupported {
		return nil, ErrConsumeOneUnsupported
	}
	for _, w := range where {
		if w.Field != "id" {
			continue
		}
		id, _ := w.Value.(string)
		row, ok := m.rows[id]
		if !ok {
			return nil, nil
		}
		delete(m.rows, id)
		return row, nil
	}
	return nil, nil
}

func (m *f10FakeAdapter) IncrementOne(_ context.Context, _ string, _ []Where, _ map[string]int, _ map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *f10FakeAdapter) Transaction(_ context.Context, fn func(Adapter) error) error {
	return fn(m)
}

func TestF10_ReserveVerificationValue_RoundTrip(t *testing.T) {
	ctx := context.Background()
	a := newF10FakeAdapter()
	expires := time.Now().UTC().Add(time.Hour)

	first, err := ReserveVerificationValue(ctx, a, "reserve:once", "reserve:once", "jti-2", expires)
	if err != nil || !first {
		t.Fatalf("first reserve = %v, %v; want true, nil", first, err)
	}
	// The row is findable under the deterministic PK with the first value.
	id := VerificationReservationID("reserve:once")
	row, err := a.FindOne(ctx, "verification", eqID(id), nil)
	if err != nil || row == nil {
		t.Fatalf("reserved row must be findable: %v %v", row, err)
	}
	if row["value"] != "jti-2" || row["identifier"] != "reserve:once" {
		t.Fatalf("reserved row must carry the first write: %v", row)
	}

	// A replay loses: first-writer-wins, original value preserved.
	second, err := ReserveVerificationValue(ctx, a, "reserve:once", "reserve:once", "jti-2-replay", expires)
	if err != nil || second {
		t.Fatalf("replay reserve = %v, %v; want false, nil", second, err)
	}
	row, _ = a.FindOne(ctx, "verification", eqID(id), nil)
	if row["value"] != "jti-2" {
		t.Fatalf("replay must not overwrite the winner: %v", row)
	}
}

func TestF10_ReserveVerificationValue_MapsRealFailure(t *testing.T) {
	ctx := context.Background()
	expires := time.Now().UTC().Add(time.Hour)

	// Unrelated store failure with no row: the error propagates, untyped.
	broken := newF10FakeAdapter()
	broken.createErr = errors.New("connection refused")
	ok, err := ReserveVerificationValue(ctx, broken, "reserve:x", "reserve:x", "v", expires)
	if ok || err == nil {
		t.Fatalf("store failure must propagate: %v %v", ok, err)
	}
	if IsDuplicateKeyError(err) {
		t.Fatalf("unrelated failure must not be typed duplicate: %v", err)
	}

	// Constraint-flavored failure with no row (missed re-read): typed.
	phantom := newF10FakeAdapter()
	phantom.createErr = errors.New(`ERROR: duplicate key value violates unique constraint "v" (SQLSTATE 23505)`)
	ok, err = ReserveVerificationValue(ctx, phantom, "reserve:y", "reserve:y", "v", expires)
	if ok || err == nil {
		t.Fatalf("phantom duplicate must propagate: %v %v", ok, err)
	}
	if !IsDuplicateKeyError(err) {
		t.Fatalf("constraint failure must be typed duplicate: %v", err)
	}
}

func TestF10_ConsumeOneWithFallback_Atomic(t *testing.T) {
	ctx := context.Background()
	a := newF10FakeAdapter()
	a.rows["c1"] = map[string]any{"id": "c1", "identifier": "tok", "value": "u1"}

	first, err := ConsumeOneWithFallback(ctx, a, "verification", eqID("c1"))
	if err != nil || first == nil || first["value"] != "u1" {
		t.Fatalf("first consume = %v, %v; want the row", first, err)
	}
	second, err := ConsumeOneWithFallback(ctx, a, "verification", eqID("c1"))
	if err != nil || second != nil {
		t.Fatalf("second consume = %v, %v; want (nil, nil)", second, err)
	}
	if a.consumeCalls != 2 {
		t.Fatalf("both consumes must go through ConsumeOne, got %d calls", a.consumeCalls)
	}
}

func TestF10_ConsumeOneWithFallback_UnsupportedFallsBack(t *testing.T) {
	ctx := context.Background()
	a := newF10FakeAdapter()
	a.consumeUnsupported = true
	a.rows["c9"] = map[string]any{"id": "c9", "identifier": "tok", "value": "u9"}

	first, err := ConsumeOneWithFallback(ctx, a, "verification", []Where{{Field: "identifier", Value: "tok"}})
	if err != nil || first == nil || first["value"] != "u9" {
		t.Fatalf("fallback consume must return the row: %v %v", first, err)
	}
	// The fallback pins the exact row by id: second consume misses.
	second, err := ConsumeOneWithFallback(ctx, a, "verification", []Where{{Field: "identifier", Value: "tok"}})
	if err != nil || second != nil {
		t.Fatalf("consumed row must be gone: %v %v", second, err)
	}
	if len(a.deletedWhere) == 0 {
		t.Fatal("fallback must delete through the transaction")
	}
	last := a.deletedWhere[len(a.deletedWhere)-1]
	if len(last) != 1 || last[0].Field != "id" || last[0].Value != "c9" {
		t.Fatalf("fallback delete must pin the row by id, got %v", last)
	}
}

func TestF10_ConsumeOneWithFallback_PassthroughError(t *testing.T) {
	ctx := context.Background()
	a := newF10FakeAdapter()
	a.consumeErr = errors.New("store exploded")
	if _, err := ConsumeOneWithFallback(ctx, a, "verification", eqID("c1")); err == nil || strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("genuine ConsumeOne failures must propagate untyped: %v", err)
	}
	if len(a.deletedWhere) != 0 {
		t.Fatal("no fallback delete on genuine ConsumeOne failure")
	}
}
