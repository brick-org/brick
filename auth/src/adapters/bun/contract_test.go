package bunadapter

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// contractMemoryAdapter is a minimal in-memory authdb.Adapter following the documented contract.
type contractMemoryAdapter struct {
	tables map[string][]map[string]any
}

func newContractMemoryAdapter() *contractMemoryAdapter {
	return &contractMemoryAdapter{tables: map[string][]map[string]any{}}
}

func contractToLogical(key string) string {
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

func contractSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func contractClone(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = v
	}
	return out
}

func contractMatches(row map[string]any, where []authdb.Where) bool {
	if len(where) == 0 {
		return true
	}
	ands := []authdb.Where{}
	ors := []authdb.Where{}
	for _, w := range where {
		if strings.EqualFold(w.Connector, "OR") {
			ors = append(ors, w)
		} else {
			ands = append(ands, w)
		}
	}
	match := func(w authdb.Where) bool {
		field := contractToLogical(w.Field)
		got := row[field]
		insensitive := strings.EqualFold(w.Mode, "insensitive")
		strEq := func(a, b any) bool {
			if insensitive {
				if as, ok := a.(string); ok {
					if bs, ok := b.(string); ok {
						return strings.EqualFold(as, bs)
					}
				}
			}
			return fmt.Sprint(a) == fmt.Sprint(b)
		}
		switch w.Operator {
		case authdb.OpNe:
			if w.Value == nil {
				_, present := row[field]
				return present && got != nil
			}
			if insensitive {
				if gs, ok := got.(string); ok {
					if ws, ok := w.Value.(string); ok {
						return !strings.EqualFold(gs, ws)
					}
				}
			}
			return fmt.Sprint(got) != fmt.Sprint(w.Value)
		case authdb.OpLt, authdb.OpLte, authdb.OpGt, authdb.OpGte:
			gf, gok := contractToFloat(got)
			wf, wok := contractToFloat(w.Value)
			if gok && wok {
				switch w.Operator {
				case authdb.OpLt:
					return gf < wf
				case authdb.OpLte:
					return gf <= wf
				case authdb.OpGt:
					return gf > wf
				}
				return gf >= wf
			}
			gs, ws := fmt.Sprint(got), fmt.Sprint(w.Value)
			switch w.Operator {
			case authdb.OpLt:
				return gs < ws
			case authdb.OpLte:
				return gs <= ws
			case authdb.OpGt:
				return gs > ws
			}
			return gs >= ws
		case authdb.OpIn, authdb.OpNotIn:
			hit := false
			rv := reflect.ValueOf(w.Value)
			if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
				for i := 0; i < rv.Len(); i++ {
					if strEq(got, rv.Index(i).Interface()) {
						hit = true
						break
					}
				}
			}
			if w.Operator == authdb.OpNotIn {
				return !hit
			}
			return hit
		case authdb.OpContains:
			if insensitive {
				return strings.Contains(strings.ToLower(fmt.Sprint(got)), strings.ToLower(fmt.Sprint(w.Value)))
			}
			return strings.Contains(fmt.Sprint(got), fmt.Sprint(w.Value))
		case authdb.OpStartsWith:
			if insensitive {
				return strings.HasPrefix(strings.ToLower(fmt.Sprint(got)), strings.ToLower(fmt.Sprint(w.Value)))
			}
			return strings.HasPrefix(fmt.Sprint(got), fmt.Sprint(w.Value))
		case authdb.OpEndsWith:
			if insensitive {
				return strings.HasSuffix(strings.ToLower(fmt.Sprint(got)), strings.ToLower(fmt.Sprint(w.Value)))
			}
			return strings.HasSuffix(fmt.Sprint(got), fmt.Sprint(w.Value))
		default:
			if w.Value == nil {
				_, present := row[field]
				return !present || got == nil
			}
			return strEq(got, w.Value)
		}
	}
	for _, w := range ands {
		if !match(w) {
			return false
		}
	}
	if len(ors) == 0 {
		return true
	}
	for _, w := range ors {
		if match(w) {
			return true
		}
	}
	return false
}

func contractCheckWhere(where []authdb.Where) error {
	for _, w := range where {
		if w.Operator == authdb.OpIn || w.Operator == authdb.OpNotIn {
			if !isSliceContractValue(w.Value) {
				return fmt.Errorf("auth: invalid where %q operator %q: Value must be an array/slice", w.Field, string(w.Operator))
			}
		}
	}
	return nil
}

func isSliceContractValue(v any) bool {
	if v == nil {
		return false
	}
	kind := reflect.ValueOf(v).Kind()
	return kind == reflect.Slice || kind == reflect.Array
}

func contractToFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func contractProject(row map[string]any, sel []string) map[string]any {
	if len(sel) == 0 {
		return contractClone(row)
	}
	out := map[string]any{}
	for _, f := range sel {
		if v, ok := row[contractSnake(f)]; ok {
			out[contractSnake(f)] = v
		}
	}
	return out
}

func (m *contractMemoryAdapter) Create(_ context.Context, model string, data map[string]any, sel []string) (map[string]any, error) {
	row := map[string]any{}
	for k, v := range data {
		row[contractToLogical(k)] = v
	}
	m.tables[model] = append(m.tables[model], row)
	return contractProject(row, sel), nil
}

func (m *contractMemoryAdapter) FindOne(_ context.Context, model string, where []authdb.Where, sel []string) (map[string]any, error) {
	if err := contractCheckWhere(where); err != nil {
		return nil, err
	}
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			return contractProject(row, sel), nil
		}
	}
	return nil, nil
}

func (m *contractMemoryAdapter) FindMany(_ context.Context, model string, where []authdb.Where, limit, offset int, sortBy *authdb.SortBy, sel []string) ([]map[string]any, error) {
	if err := contractCheckWhere(where); err != nil {
		return nil, err
	}
	var rows []map[string]any
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			rows = append(rows, contractProject(row, sel))
		}
	}
	if sortBy != nil {
		field := contractToLogical(sortBy.Field)
		desc := strings.EqualFold(sortBy.Direction, "desc")
		sort.SliceStable(rows, func(i, j int) bool {
			gi, gj := fmt.Sprint(rows[i][field]), fmt.Sprint(rows[j][field])
			if desc {
				return gi > gj
			}
			return gi < gj
		})
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rows) {
		return []map[string]any{}, nil
	}
	rows = rows[offset:]
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	return rows, nil
}

func (m *contractMemoryAdapter) Count(_ context.Context, model string, where []authdb.Where) (int, error) {
	if err := contractCheckWhere(where); err != nil {
		return 0, err
	}
	n := 0
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			n++
		}
	}
	return n, nil
}

func (m *contractMemoryAdapter) Update(_ context.Context, model string, where []authdb.Where, data map[string]any) (map[string]any, error) {
	if len(where) == 0 {
		return nil, nil
	}
	if err := contractCheckWhere(where); err != nil {
		return nil, err
	}
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			for k, v := range data {
				row[contractToLogical(k)] = v
			}
			return contractClone(row), nil
		}
	}
	return nil, nil
}

func (m *contractMemoryAdapter) UpdateMany(_ context.Context, model string, where []authdb.Where, data map[string]any) (int, error) {
	if err := contractCheckWhere(where); err != nil {
		return 0, err
	}
	n := 0
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			for k, v := range data {
				row[contractToLogical(k)] = v
			}
			n++
		}
	}
	return n, nil
}

func (m *contractMemoryAdapter) Delete(_ context.Context, model string, where []authdb.Where) error {
	if len(where) == 0 {
		return nil
	}
	if err := contractCheckWhere(where); err != nil {
		return err
	}
	kept := m.tables[model][:0]
	for _, row := range m.tables[model] {
		if !contractMatches(row, where) {
			kept = append(kept, row)
		}
	}
	m.tables[model] = kept
	return nil
}

func (m *contractMemoryAdapter) DeleteMany(_ context.Context, model string, where []authdb.Where) (int, error) {
	if err := contractCheckWhere(where); err != nil {
		return 0, err
	}
	kept := m.tables[model][:0]
	for _, row := range m.tables[model] {
		if !contractMatches(row, where) {
			kept = append(kept, row)
		}
	}
	n := len(m.tables[model]) - len(kept)
	m.tables[model] = kept
	return n, nil
}

func (m *contractMemoryAdapter) ConsumeOne(_ context.Context, model string, where []authdb.Where) (map[string]any, error) {
	if len(where) == 0 {
		return nil, nil
	}
	if err := contractCheckWhere(where); err != nil {
		return nil, err
	}
	for i, row := range m.tables[model] {
		if contractMatches(row, where) {
			consumed := contractClone(row)
			m.tables[model] = append(m.tables[model][:i], m.tables[model][i+1:]...)
			return consumed, nil
		}
	}
	return nil, nil
}

func (m *contractMemoryAdapter) IncrementOne(_ context.Context, model string, where []authdb.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	if len(increment) == 0 && len(set) == 0 {
		return nil, fmt.Errorf("auth: incrementOne requires a non-empty increment or set")
	}
	if len(where) == 0 {
		return nil, nil
	}
	if err := contractCheckWhere(where); err != nil {
		return nil, err
	}
	for _, row := range m.tables[model] {
		if contractMatches(row, where) {
			for logical, delta := range increment {
				key := contractToLogical(logical)
				cur, _ := contractToNumber(row[key])
				row[key] = cur + delta
			}
			for k, v := range set {
				row[contractToLogical(k)] = v
			}
			return contractClone(row), nil
		}
	}
	return nil, nil
}

func contractToNumber(v any) (int, bool) {
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

func (m *contractMemoryAdapter) Transaction(ctx context.Context, fn func(tx authdb.Adapter) error) error {
	clone := newContractMemoryAdapter()
	for model, rows := range m.tables {
		for _, row := range rows {
			clone.tables[model] = append(clone.tables[model], contractClone(row))
		}
	}
	if err := fn(clone); err != nil {
		return err
	}
	m.tables = clone.tables
	return nil
}

func TestContract_SelectProjection(t *testing.T) {
	ctx := context.Background()
	m := newContractMemoryAdapter()
	if _, err := m.Create(ctx, "user", map[string]any{"id": "1", "email": "a@b.c", "name": "Al"}, nil); err != nil {
		t.Fatal(err)
	}
	row, err := m.FindOne(ctx, "user", []authdb.Where{{Field: "id", Value: "1"}}, []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 1 || row["email"] != "a@b.c" {
		t.Fatalf("FindOne select must project to selected snake keys: %v", row)
	}
	created, err := m.Create(ctx, "user", map[string]any{"id": "2", "email": "b@c.d", "name": "Bo"}, []string{"id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created["id"] != "2" {
		t.Fatalf("Create select must project: %v", created)
	}
	rows, err := m.FindMany(ctx, "user", nil, 0, 0, nil, []string{"name"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[0]) != 1 {
		t.Fatalf("FindMany select must project every row: %v", rows)
	}
}

func TestContract_UpdateNilOnNoMatch(t *testing.T) {
	ctx := context.Background()
	m := newContractMemoryAdapter()
	if _, err := m.Create(ctx, "user", map[string]any{"id": "1", "name": "Al"}, nil); err != nil {
		t.Fatal(err)
	}
	row, err := m.Update(ctx, "user", []authdb.Where{{Field: "id", Value: "missing"}}, map[string]any{"name": "X"})
	if err != nil || row != nil {
		t.Fatalf("Update no match must be (nil,nil), got %v %v", row, err)
	}
	row, err = m.Update(ctx, "user", nil, map[string]any{"name": "X"})
	if err != nil || row != nil {
		t.Fatalf("Update empty where must be (nil,nil), got %v %v", row, err)
	}
	kept, _ := m.FindOne(ctx, "user", []authdb.Where{{Field: "id", Value: "1"}}, nil)
	if kept["name"] != "Al" {
		t.Fatalf("empty-where Update must not mutate: %v", kept)
	}
}

func TestContract_CountSemantics(t *testing.T) {
	ctx := context.Background()
	m := newContractMemoryAdapter()
	for _, id := range []string{"1", "2", "3"} {
		if _, err := m.Create(ctx, "user", map[string]any{"id": id, "role": "member"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	n, err := m.UpdateMany(ctx, "user", []authdb.Where{{Field: "role", Value: "member"}}, map[string]any{"role": "admin"})
	if err != nil || n != 3 {
		t.Fatalf("UpdateMany must return affected count, got %d %v", n, err)
	}
	n, err = m.UpdateMany(ctx, "user", []authdb.Where{{Field: "role", Value: "nobody"}}, map[string]any{"role": "x"})
	if err != nil || n != 0 {
		t.Fatalf("UpdateMany no match must be 0, got %d %v", n, err)
	}
	n, err = m.DeleteMany(ctx, "user", []authdb.Where{{Field: "role", Value: "admin"}})
	if err != nil || n != 3 {
		t.Fatalf("DeleteMany must return deleted count, got %d %v", n, err)
	}
	n, err = m.DeleteMany(ctx, "user", []authdb.Where{{Field: "role", Value: "admin"}})
	if err != nil || n != 0 {
		t.Fatalf("DeleteMany no match must be 0, got %d %v", n, err)
	}
	left, err := m.Count(ctx, "user", nil)
	if err != nil || left != 0 {
		t.Fatalf("Count after DeleteMany must be 0, got %d %v", left, err)
	}
}
