package auth

import (
	"net/http"
	"reflect"
)

// splitPatchOptions extracts sourced collections from an init option patch.
// DatabaseHooks and TrustedOrigins/TrustedOriginsFunc are collected with
// plugin:<id> source labels (mirroring runPluginInit); the remainder merges
// defu-style. It returns the extracted hooks, statics, dynamic func, and the
// rest patch with those fields zeroed.
func splitPatchOptions(patch Options) (DBHooks, []string, func(*http.Request) []string, Options) {
	dbHooks := patch.DatabaseHooks
	statics := append([]string(nil), patch.TrustedOrigins...)
	dyn := patch.TrustedOriginsFunc
	rest := patch
	rest.DatabaseHooks = nil
	rest.TrustedOrigins = nil
	rest.TrustedOriginsFunc = nil
	return dbHooks, statics, dyn, rest
}

// defuOptions merges patch into base defu-style: existing (base) values win,
// patch fills only missing (zero) values.
// Upstream TypeScript name: defu (option merge).
//
// DEVIATION (structural, loud): defu skips only null/undefined base values,
// so an explicit upstream `false`/`0`/`""` beats a patch value. Go zero
// values conflate "unset" with an explicit falsy, so plain scalar kinds
// (bool, string, int) cannot preserve an explicit falsy against a non-zero
// patch — the patch fills. Presence-tracked kinds (pointers, slices, maps,
// funcs, interfaces) honor base-wins exactly. Pinned by
// TestInitDefuScalarZeroValueDeviation.
func defuOptions(base *Options, patch Options) {
	defuReflect(reflect.ValueOf(base).Elem(), reflect.ValueOf(patch))
}

func defuReflect(base, patch reflect.Value) {
	if base.Kind() != reflect.Struct || patch.Kind() != reflect.Struct {
		return
	}
	t := base.Type()
	for i := 0; i < base.NumField(); i++ {
		bf := base.Field(i)
		pf := patch.FieldByName(t.Field(i).Name)
		if !pf.IsValid() || !bf.CanSet() {
			continue
		}
		if isZeroValue(pf) {
			continue
		}
		if isZeroValue(bf) {
			switch pf.Kind() {
			case reflect.Slice:
				if pf.IsNil() {
					continue
				}
				cp := reflect.MakeSlice(pf.Type(), 0, pf.Len())
				cp = reflect.AppendSlice(cp, pf)
				bf.Set(cp)
			case reflect.Map:
				if pf.IsNil() {
					continue
				}
				cp := reflect.MakeMapWithSize(pf.Type(), pf.Len())
				for _, k := range pf.MapKeys() {
					cp.SetMapIndex(k, pf.MapIndex(k))
				}
				bf.Set(cp)
			case reflect.Pointer:
				if pf.IsNil() {
					continue
				}
				cp := reflect.New(pf.Type().Elem())
				cp.Elem().Set(pf.Elem())
				bf.Set(cp)
			default:
				bf.Set(pf)
			}
			continue
		}
		// Both non-zero: recurse/merge by kind, base wins on conflict.
		switch bf.Kind() {
		case reflect.Struct:
			defuReflect(bf, pf)
		case reflect.Slice:
			combined := reflect.MakeSlice(bf.Type(), 0, bf.Len()+pf.Len())
			combined = reflect.AppendSlice(combined, bf)
			combined = reflect.AppendSlice(combined, pf)
			bf.Set(combined)
		case reflect.Map:
			if bf.IsNil() {
				bf.Set(pf)
				continue
			}
			if pf.IsNil() {
				continue
			}
			for _, k := range pf.MapKeys() {
				pv := pf.MapIndex(k)
				bv := bf.MapIndex(k)
				if !bv.IsValid() {
					bf.SetMapIndex(k, pv)
					continue
				}
				if bv.Type() == pv.Type() && bv.Kind() == reflect.Struct {
					baseCopy := reflect.New(bv.Type()).Elem()
					baseCopy.Set(bv)
					patchCopy := reflect.New(pv.Type()).Elem()
					patchCopy.Set(pv)
					defuReflect(baseCopy, patchCopy)
					bf.SetMapIndex(k, baseCopy)
				}
			}
		case reflect.Pointer:
			if bf.Type() == pf.Type() && bf.Type().Elem().Kind() == reflect.Struct &&
				!bf.IsNil() && !pf.IsNil() {
				defuReflect(bf.Elem(), pf.Elem())
			}
		default:
		}
	}
}

func isZeroValue(v reflect.Value) bool {
	// reflect.Value.IsZero reports whether v is the zero value for its type.
	// It panics on invalid values; callers guard with IsValid.
	return v.IsZero()
}

// overwriteOptions merges patch into base patch-wins: non-zero patch fields
// overwrite base.
func overwriteOptions(base *Options, patch Options) {
	overwriteReflect(reflect.ValueOf(base).Elem(), reflect.ValueOf(patch))
}

func overwriteReflect(base, patch reflect.Value) {
	if base.Kind() != reflect.Struct || patch.Kind() != reflect.Struct {
		return
	}
	t := base.Type()
	for i := 0; i < base.NumField(); i++ {
		bf := base.Field(i)
		pf := patch.FieldByName(t.Field(i).Name)
		if !pf.IsValid() || !bf.CanSet() {
			continue
		}
		if isZeroValue(pf) {
			continue
		}
		if bf.Kind() == reflect.Struct && pf.Kind() == reflect.Struct {
			overwriteReflect(bf, pf)
			continue
		}
		bf.Set(pf)
	}
}

// isOptionsZero reports whether o is the zero Options (no patch).
func isOptionsZero(o Options) bool {
	return isZeroValue(reflect.ValueOf(o))
}

// combineTrustedOriginsFuncs chains dynamic origin resolvers.
// Nil entries are skipped.
func combineTrustedOriginsFuncs(funcs []func(*http.Request) []string) func(*http.Request) []string {
	valid := make([]func(*http.Request) []string, 0, len(funcs))
	for _, fn := range funcs {
		if fn != nil {
			valid = append(valid, fn)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if len(valid) == 1 {
		return valid[0]
	}
	return func(r *http.Request) []string {
		var out []string
		for _, fn := range valid {
			out = append(out, fn(r)...)
		}
		return out
	}
}

// filterNonEmpty drops empty strings.
func filterNonEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	// Preserve nil vs empty: upstream returns [] (possibly empty); keep slice.
	if out == nil {
		return []string{}
	}
	return out
}
