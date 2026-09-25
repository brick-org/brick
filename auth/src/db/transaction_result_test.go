package db

import (
	"context"
	"errors"
	"testing"
)

// Port of upstream createAsIsTransaction contract (factory.ts:46-48, index.ts:506-509): generic R, sequential fallback.

func TestTransactionResult_ReturnsCallbackValue(t *testing.T) {
	ctx := context.Background()
	m := &seqAdapter{tables: map[string][]map[string]any{}}
	got, err := TransactionResult(ctx, m, func(tx Adapter) (string, error) {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "r1"}, nil); err != nil {
			return "", err
		}
		return "hello", nil
	})
	if err != nil || got != "hello" {
		t.Fatalf("TransactionResult = %q, %v; want hello, nil", got, err)
	}
	if row, _ := m.FindOne(ctx, "widget", []Where{{Field: "id", Value: "r1"}}, nil); row == nil {
		t.Fatal("sequential fallback must apply the write")
	}
}

func TestTransactionResult_PropagatesCallbackError(t *testing.T) {
	ctx := context.Background()
	m := &seqAdapter{tables: map[string][]map[string]any{}}
	boom := errors.New("boom")
	_, err := TransactionResult(ctx, m, func(tx Adapter) (int, error) {
		return 0, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("TransactionResult err = %v, want boom", err)
	}
}

func TestTransactionResult_SequentialFallbackWithoutBreakingAdapter(t *testing.T) {
	ctx := context.Background()
	m := &seqAdapter{tables: map[string][]map[string]any{}, noTx: true}
	got, err := TransactionResult(ctx, m, func(tx Adapter) (int, error) {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "s1"}, nil); err != nil {
			return 0, err
		}
		return 42, nil
	})
	if err != nil || got != 42 {
		t.Fatalf("sequential fallback = %d, %v; want 42, nil", got, err)
	}
}

type seqAdapter struct {
	tables map[string][]map[string]any
	noTx   bool
}

func (m *seqAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	row := map[string]any{}
	for k, v := range data {
		row[k] = v
	}
	m.tables[model] = append(m.tables[model], row)
	return row, nil
}
func (m *seqAdapter) FindOne(_ context.Context, model string, where []Where, _ []string) (map[string]any, error) {
	for _, row := range m.tables[model] {
		match := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				match = false
			}
		}
		if match {
			return row, nil
		}
	}
	return nil, nil
}
func (m *seqAdapter) FindMany(_ context.Context, model string, _ []Where, _, _ int, _ *SortBy, _ []string) ([]map[string]any, error) {
	return m.tables[model], nil
}
func (m *seqAdapter) Count(_ context.Context, model string, _ []Where) (int, error) {
	return len(m.tables[model]), nil
}
func (m *seqAdapter) Update(_ context.Context, model string, where []Where, data map[string]any) (map[string]any, error) {
	for _, row := range m.tables[model] {
		match := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				match = false
			}
		}
		if match {
			for k, v := range data {
				row[k] = v
			}
			return row, nil
		}
	}
	return nil, nil
}
func (m *seqAdapter) UpdateMany(_ context.Context, model string, where []Where, data map[string]any) (int, error) {
	n := 0
	for _, row := range m.tables[model] {
		match := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				match = false
			}
		}
		if match {
			for k, v := range data {
				row[k] = v
			}
			n++
		}
	}
	return n, nil
}
func (m *seqAdapter) Delete(_ context.Context, model string, where []Where) error {
	kept := m.tables[model][:0]
	for _, row := range m.tables[model] {
		drop := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				drop = false
			}
		}
		if !drop {
			kept = append(kept, row)
		}
	}
	m.tables[model] = kept
	return nil
}
func (m *seqAdapter) DeleteMany(_ context.Context, model string, where []Where) (int, error) {
	before := len(m.tables[model])
	_ = m.Delete(context.Background(), model, where)
	return before - len(m.tables[model]), nil
}
func (m *seqAdapter) ConsumeOne(_ context.Context, model string, where []Where) (map[string]any, error) {
	for i, row := range m.tables[model] {
		match := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				match = false
			}
		}
		if match {
			m.tables[model] = append(m.tables[model][:i], m.tables[model][i+1:]...)
			return row, nil
		}
	}
	return nil, nil
}
func (m *seqAdapter) IncrementOne(_ context.Context, model string, where []Where, inc map[string]int, set map[string]any) (map[string]any, error) {
	for _, row := range m.tables[model] {
		match := true
		for _, w := range where {
			if row[w.Field] != w.Value {
				match = false
			}
		}
		if match {
			for k, d := range inc {
				cur, _ := row[k].(int)
				row[k] = cur + d
			}
			for k, v := range set {
				row[k] = v
			}
			return row, nil
		}
	}
	return nil, nil
}
func (m *seqAdapter) Transaction(_ context.Context, fn func(Adapter) error) error {
	return fn(m)
}
