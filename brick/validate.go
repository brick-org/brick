package brick

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/brick-org/brick/brick/db"
	"github.com/brick-org/brick/dsl/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"
)

// FieldError is one validation failure: machine-readable code plus a
// human message, lowered to the 422 envelope by Unprocessable.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Validation collects field failures instead of returning the first bare
// error, so clients get the full actionable list in one 422 round-trip:
//
//	v.Required("Name", deal.Name)
//	v.Email("Email", c.Email) // skip-if-empty at call site, as today
//	v.Range("Probability", d.Probability, 0, 100)
//	if errs := v.Errs(); errs != nil { return brick.Unprocessable(errs) }
type Validation struct {
	errs []FieldError
}

// Add records a failure with an explicit code and message.
func (v *Validation) Add(field, code, message string) {
	v.errs = append(v.errs, FieldError{Field: field, Code: code, Message: message})
}

// Required fails on missing/blank values. Numbers and bools count as
// present (0 and false are meaningful); only nil and blank strings fail.
func (v *Validation) Required(field string, value any) {
	if value == nil {
		v.Add(field, "required", field+" is required")
		return
	}
	if s, ok := value.(string); ok && strings.TrimSpace(s) == "" {
		v.Add(field, "required", field+" is required")
	}
}

// Email fails on malformed non-empty values; empty is skipped (pair with
// Required when the address is mandatory). Deliberately shallow —
// deliverability is not a validator's job.
func (v *Validation) Email(field, value string) {
	if value == "" {
		return
	}
	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 || !strings.Contains(value[at:], ".") || strings.Contains(value, " ") {
		v.Add(field, "email", field+" must be a valid email address")
	}
}

// Domain fails on malformed non-empty domains; empty is skipped.
func (v *Validation) Domain(field, value string) {
	if value == "" {
		return
	}
	if strings.Contains(value, " ") || !strings.Contains(value, ".") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		v.Add(field, "domain", field+" must be a valid domain")
	}
}

// Range fails when val is outside [min, max].
func (v *Validation) Range(field string, val, min, max float64) {
	if val < min || val > max {
		v.Add(field, "range", field+" must be between "+strconv.FormatFloat(min, 'f', -1, 64)+
			" and "+strconv.FormatFloat(max, 'f', -1, 64))
	}
}

// Errs returns the collected failures, or nil when valid.
func (v *Validation) Errs() []FieldError {
	if len(v.errs) == 0 {
		return nil
	}
	return v.errs
}

// ─── Schema validation (exec pipeline) ─────────────────────────────────────
//
// Order per 006 §3.1: unknown-key strip → readonly-strip → from-injection
// (server authority, OVERWRITES client) → defaults → field checks.

func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) == ""
	}
	return false
}

// stripUnknownKeys deletes keys outside the schema allowlist (mass-assignment
// guard). Unknown keys never reach InsertMap/Update.
func stripUnknownKeys(r ResourceConfig, body map[string]any) map[string]any {
	if r.Schema == nil {
		return body
	}
	for k := range body {
		if !r.hasSchemaField(k) {
			delete(body, k)
		}
	}
	return body
}

// applyFromSources injects server-authoritative values from the request
// identity, OVERWRITING any client-sent value. (Beta kept a client-sent
// value, which let `user_id` spoofing succeed for pages.) Missing +
// non-optional + unauthenticated → 401. Runs on every write, so updates
// cannot transfer ownership either.
func applyFromSources(ctx context.Context, r ResourceConfig, body map[string]any) error {
	if r.Schema == nil {
		return nil
	}
	appCtx := appCtxFromContext(ctx)
	for name, f := range r.Schema.Fields {
		if f.FromSource == "" {
			continue
		}
		if v := resolveFromAppCtx(appCtx, f.FromSource); v != nil {
			body[name] = v
			continue
		}
		if f.IsOptional {
			continue
		}
		return huma.Error401Unauthorized("cannot resolve " + name + " from " + f.FromSource + " (authentication required)")
	}
	return nil
}

// validateCreateBody checks required/maxlen/enum on a create body.
// The PK column is autoname-owned (except prompt, which must be present).
func validateCreateBody(r ResourceConfig, body map[string]any) error {
	if r.Schema == nil {
		return nil
	}
	pkCol := r.pkColumn()
	var v Validation
	for name, f := range r.Schema.Fields {
		val, present := body[name]
		if name == pkCol {
			if r.pkIsPrompt() && isEmptyValue(val) {
				v.Add(name, "required", name+" is required")
			}
			continue
		}
		if f.IsRequired && !presentOrFilled(present, val) {
			v.Add(name, "required", name+" is required")
			continue
		}
		checkFieldShape(&v, name, f, present, val)
	}
	if errs := v.Errs(); errs != nil {
		return Unprocessable(errs)
	}
	return nil
}

// validateUpdateBody checks maxlen/enum for the fields present in a partial
// update. Required is deliberately NOT checked — updates are partial.
func validateUpdateBody(r ResourceConfig, body map[string]any) error {
	if r.Schema == nil {
		return nil
	}
	var v Validation
	for name, f := range r.Schema.Fields {
		val, present := body[name]
		if !present {
			continue
		}
		checkFieldShape(&v, name, f, true, val)
	}
	if errs := v.Errs(); errs != nil {
		return Unprocessable(errs)
	}
	return nil
}

func presentOrFilled(present bool, val any) bool {
	return present && !isEmptyValue(val)
}

func checkFieldShape(v *Validation, name string, f *schema.FieldDef, present bool, val any) {
	if !present || val == nil {
		return
	}
	if f.MaxLength > 0 {
		if s, ok := val.(string); ok && utf8.RuneCountInString(s) > f.MaxLength {
			v.Add(name, "maxlen", name+" exceeds maximum length")
		}
	}
	if len(f.EnumValues) > 0 {
		s, ok := val.(string)
		if !ok {
			v.Add(name, "enum", name+" must be one of the allowed values")
			return
		}
		allowed := false
		for _, e := range f.EnumValues {
			if e == s {
				allowed = true
				break
			}
		}
		if !allowed {
			v.Add(name, "enum", name+" must be one of the allowed values")
		}
	}
}

// checkUniquePrecheck fails with 409 when a unique field value already
// exists in another row. Call inside the write tx, after hooks (hooks may
// fill values). Identifiers travel as bun.Ident, values as placeholders.
// Races still resolve to 409 on PG 23505.
func checkUniquePrecheck(ctx context.Context, txDB *db.DB, r ResourceConfig, body, previous map[string]any) error {
	if r.Schema == nil {
		return nil
	}
	for name, f := range r.Schema.Fields {
		if !f.IsUnique {
			continue
		}
		val, present := body[name]
		if !presentOrFilled(present, val) {
			continue
		}
		var one int64
		var err error
		if previous == nil {
			err = txDB.Raw(ctx, &one,
				"SELECT 1 FROM ? WHERE ? = ? LIMIT 1",
				bun.Ident(r.tableName()), bun.Ident(name), val)
		} else {
			err = txDB.Raw(ctx, &one,
				"SELECT 1 FROM ? WHERE ? = ? AND ? != ? LIMIT 1",
				bun.Ident(r.tableName()), bun.Ident(name), val,
				bun.Ident(r.lookupField()), previous[r.lookupField()])
		}
		if err == nil {
			return Conflict(name + " already exists")
		}
		if err != sql.ErrNoRows {
			return err
		}
	}
	return nil
}
