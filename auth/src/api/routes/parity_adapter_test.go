package routes

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

var errEmptyIncrement = errors.New("auth: incrementOne requires a non-empty increment or set")

func parityToNumber(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, true
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// parityMemAdapter is a minimal in-memory types.Adapter for parity unit
// tests. Rows are stored with snake_case keys, mirroring the physical
// row-key contract route code reads.
type parityMemAdapter struct {
	mu     sync.Mutex
	tables map[string][]map[string]any
}

func newParityMemAdapter() *parityMemAdapter {
	return &parityMemAdapter{tables: map[string][]map[string]any{}}
}

func parityToLogical(key string) string {
	if key == "" {
		return key
	}
	hasUnderscore := false
	for _, r := range key {
		if r == '_' {
			hasUnderscore = true
			break
		}
	}
	if !hasUnderscore {
		return key
	}
	var b strings.Builder
	upperNext := false
	for i, r := range key {
		if r == '_' {
			upperNext = i > 0
			continue
		}
		if upperNext && r >= 'a' && r <= 'z' {
			b.WriteRune(r - ('a' - 'A'))
			upperNext = false
			continue
		}
		upperNext = false
		b.WriteRune(r)
	}
	return b.String()
}

func paritySnake(key string) string {
	var out strings.Builder
	for i, r := range key {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				out.WriteByte('_')
			}
			out.WriteRune(r + ('a' - 'A'))
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func parityNormalize(data map[string]any) map[string]any {
	row := make(map[string]any, len(data))
	for key, value := range data {
		row[parityToLogical(key)] = value
	}
	return row
}

func parityClone(row map[string]any) map[string]any {
	cloned := make(map[string]any, len(row))
	for key, value := range row {
		cloned[key] = value
	}
	return cloned
}

func parityMatches(row map[string]any, where []types.Where) bool {
	result := true
	for i, clause := range where {
		matches := parityClauseMatches(row, clause)
		if i == 0 {
			result = matches
			continue
		}
		if strings.EqualFold(clause.Connector, "OR") {
			result = result || matches
		} else {
			result = result && matches
		}
	}
	return result
}

// parityClauseMatches evaluates one where clause, honoring comparison
// operators for time.Time and numeric cells (needed by secondary-storage
// live-row guards and verification expiry sweeps). Unknown operators fall
// back to equality, preserving the historical behavior for eq-only callers.
func parityClauseMatches(row map[string]any, clause types.Where) bool {
	op := clause.Operator
	if op == "" || op == types.OpEq {
		return row[parityToLogical(clause.Field)] == clause.Value
	}
	got := row[parityToLogical(clause.Field)]
	switch op {
	case types.OpLt, types.OpLte, types.OpGt, types.OpGte:
		cmp := parityCompareValues(got, clause.Value)
		switch op {
		case types.OpLt:
			return cmp < 0
		case types.OpLte:
			return cmp <= 0
		case types.OpGt:
			return cmp > 0
		default:
			return cmp >= 0
		}
	default:
		return got == clause.Value
	}
}

// parityCompareValues orders two cells, supporting time.Time and numerics.
// Incomparable pairs compare as equal (0) so guarded clauses simply miss.
func parityCompareValues(got, want any) int {
	if gotTime, ok := got.(time.Time); ok {
		if wantTime, ok := want.(time.Time); ok {
			switch {
			case gotTime.Before(wantTime):
				return -1
			case gotTime.After(wantTime):
				return 1
			default:
				return 0
			}
		}
		return 0
	}
	gotNum, gotOk := parityToNumber(got)
	wantNum, wantOk := parityToNumber(want)
	if !gotOk || !wantOk {
		return 0
	}
	switch {
	case gotNum < wantNum:
		return -1
	case gotNum > wantNum:
		return 1
	default:
		return 0
	}
}

func (m *parityMemAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := parityNormalize(data)
	m.tables[model] = append(m.tables[model], row)
	return parityClone(row), nil
}

func (m *parityMemAdapter) FindOne(_ context.Context, model string, where []types.Where, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.tables[model] {
		if parityMatches(row, where) {
			return parityClone(row), nil
		}
	}
	return nil, nil
}

func (m *parityMemAdapter) FindMany(_ context.Context, model string, where []types.Where, limit, offset int, _ *types.SortBy, _ []string) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make([]map[string]any, 0)
	for _, row := range m.tables[model] {
		if parityMatches(row, where) {
			rows = append(rows, parityClone(row))
		}
	}
	return rows, nil
}

func (m *parityMemAdapter) Count(_ context.Context, model string, where []types.Where) (int, error) {
	rows, _ := m.FindMany(context.Background(), model, where, 0, 0, nil, nil)
	return len(rows), nil
}

func (m *parityMemAdapter) Update(_ context.Context, model string, where []types.Where, data map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	update := parityNormalize(data)
	for _, row := range m.tables[model] {
		if parityMatches(row, where) {
			for key, value := range update {
				row[key] = value
			}
			return parityClone(row), nil
		}
	}
	return nil, nil
}

func (m *parityMemAdapter) UpdateMany(_ context.Context, model string, where []types.Where, data map[string]any) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	update := parityNormalize(data)
	updated := 0
	for _, row := range m.tables[model] {
		if parityMatches(row, where) {
			for key, value := range update {
				row[key] = value
			}
			updated++
		}
	}
	return updated, nil
}

func (m *parityMemAdapter) Delete(_ context.Context, model string, where []types.Where) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.tables[model][:0]
	for _, row := range m.tables[model] {
		if !parityMatches(row, where) {
			filtered = append(filtered, row)
		}
	}
	m.tables[model] = filtered
	return nil
}

func (m *parityMemAdapter) DeleteMany(ctx context.Context, model string, where []types.Where) (int, error) {
	allBefore, _ := m.FindMany(ctx, model, nil, 0, 0, nil, nil)
	if err := m.Delete(ctx, model, where); err != nil {
		return 0, err
	}
	allAfter, _ := m.FindMany(ctx, model, nil, 0, 0, nil, nil)
	return len(allBefore) - len(allAfter), nil
}

func (m *parityMemAdapter) ConsumeOne(_ context.Context, model string, where []types.Where) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, row := range m.tables[model] {
		if parityMatches(row, where) {
			consumed := parityClone(row)
			m.tables[model] = append(m.tables[model][:i], m.tables[model][i+1:]...)
			return consumed, nil
		}
	}
	return nil, nil
}

func (m *parityMemAdapter) IncrementOne(_ context.Context, model string, where []types.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(increment) == 0 && len(set) == 0 {
		return nil, errEmptyIncrement
	}
	for _, row := range m.tables[model] {
		if parityMatches(row, where) {
			for logical, delta := range increment {
				key := parityToLogical(logical)
				cur, _ := parityToNumber(row[key])
				row[key] = cur + delta
			}
			for k, v := range parityNormalize(set) {
				row[k] = v
			}
			return parityClone(row), nil
		}
	}
	return nil, nil
}

func (m *parityMemAdapter) Transaction(_ context.Context, fn func(tx types.Adapter) error) error {
	m.mu.Lock()
	clone := newParityMemAdapter()
	for model, rows := range m.tables {
		for _, row := range rows {
			clone.tables[model] = append(clone.tables[model], parityClone(row))
		}
	}
	m.mu.Unlock()
	if err := fn(clone); err != nil {
		return err
	}
	m.mu.Lock()
	m.tables = clone.tables
	m.mu.Unlock()
	return nil
}

func parityTestOptions(db types.Adapter) types.Options {
	return types.Options{Secret: "parity-secret", DB: db}
}

func parityCreateUser(t *testing.T, db types.Adapter, email string, verified bool) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "user", map[string]any{
		"id":    "user-" + strings.ReplaceAll(email, "@", "-at-"),
		"email": email, "emailVerified": verified, "name": "Parity",
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("create user: %v", err)
	}
}
