package routes

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// This file mirrors the input/output field handling in
// vendor/better-auth/packages/better-auth/src/db/schema.ts (parseInputData,
// parseSessionInput, filterOutputFields via @better-auth/core/utils/db) for
// the session/user additional-field surface owned here.
//
// Contract split (see auth/schema.go FullSchema vs ResolveSchema): the legacy
// extractAdditionalFields/filterSessionUpdateFields (session_extra.go) treat
// a non-empty declared map as an allow-list over plugin-only fields. The
// Full-suffixed helpers below process the FULL schema (core + plugin +
// option additionalFields) with upstream input/output semantics. Output
// helpers union — never intersect — with legacy acceptance: fields unknown
// to the full schema keep the passthrough so migrating output consumers
// never newly strip previously returned fields. The session-update input
// filter instead drops unknown keys per upstream parseInputData, so
// unknown-only bodies 400 ("No fields to update").

// FieldParseError carries a Better Auth error code for input parsing
// failures, mirroring the APIError codes thrown by upstream parseInputData:
// FIELD_NOT_ALLOWED (input:false set), MISSING_FIELD (required on create),
// VALIDATION_ERROR (validator input rejection). Transform failures propagate
// the transform's own error (upstream lets them throw).
type FieldParseError struct {
	// Code is the Better Auth error code (types.ErrFieldNotAllowed,
	// types.ErrMissingField, types.ErrValidationError).
	Code string
	// Field is the logical field that failed.
	Field string
	// Message is the human-readable detail.
	Message string
}

func (e *FieldParseError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// CanonicalInputKey resolves a body/row key to its logical field name,
// honoring model aliases at the field level: exact logical match first,
// then explicit FieldName reverse map (e.g. "email_address" -> "email"),
// then snake_case folding ("expires_at" -> "expiresAt", mirroring
// snakeToCamel). It reports false for unknown keys. Go-only helper;
// upstream parseInputData iterates schema fields and matches logical keys
// directly (callers there already hold logical names), while route bodies
// here may carry physical spellings.
func CanonicalInputKey(key string, fields map[string]types.FieldAttribute) (string, bool) {
	if _, ok := fields[key]; ok {
		return key, true
	}
	for name, attr := range fields {
		if attr.FieldName != "" && attr.FieldName == key {
			return name, true
		}
	}
	if camel := snakeToCamel(key); camel != key {
		if _, ok := fields[camel]; ok {
			return camel, true
		}
		for name, attr := range fields {
			if attr.FieldName != "" && attr.FieldName == camel {
				return name, true
			}
		}
	}
	return "", false
}

// ParseInputData ports upstream parseInputData (db/schema.ts) for one
// model's field map: it walks schema fields (unknown data keys are ignored,
// never copied), enforces input:false (default substituted on create, truthy
// values rejected with FIELD_NOT_ALLOWED), runs validator input hooks
// (rejection wrapped as VALIDATION_ERROR) and transform input hooks
// (errors abort raw), applies func/static defaults on create, and enforces
// required on create with MISSING_FIELD. action is "create" (default when
// empty) or "update" (no defaults, no required checks).
//
// Upstream TypeScript name: parseInputData.
func ParseInputData(data map[string]any, fields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	if action == "" {
		action = "create"
	}
	parsed := make(map[string]any)
	// Canonicalize incoming keys once so physical spellings match logical
	// schema fields (model-alias honoring at the field level).
	canonical := make(map[string]any, len(data))
	for key, value := range data {
		if name, ok := CanonicalInputKey(key, fields); ok {
			canonical[name] = value
		} else {
			canonical[key] = value
		}
	}
	for key, field := range fields {
		value, present := canonical[key]
		if present {
			if field.Input != nil && !*field.Input {
				if field.DefaultValue != nil {
					if action != "update" {
						parsed[key] = defaultValueOf(field)
						continue
					}
				}
				if isTruthy(value) {
					return nil, &FieldParseError{
						Code:    types.ErrFieldNotAllowed,
						Field:   key,
						Message: fmt.Sprintf("%s is not allowed to be set", key),
					}
				}
				continue
			}
			if field.Validator != nil && field.Validator.Input != nil && value != nil {
				if err := field.Validator.Input.Validate(value); err != nil {
					return nil, &FieldParseError{
						Code:    types.ErrValidationError,
						Field:   key,
						Message: err.Error(),
					}
				}
				parsed[key] = value
				continue
			}
			if field.Transform != nil && field.Transform.Input != nil && value != nil {
				out, err := field.Transform.Input(value)
				if err != nil {
					return nil, err
				}
				parsed[key] = out
				continue
			}
			parsed[key] = value
			continue
		}
		if field.DefaultValue != nil && action == "create" {
			parsed[key] = defaultValueOf(field)
			continue
		}
		if (field.Required == nil || *field.Required) && action == "create" {
			return nil, &FieldParseError{
				Code:    types.ErrMissingField,
				Field:   key,
				Message: fmt.Sprintf("%s is required", key),
			}
		}
	}
	return parsed, nil
}

// FilterOutputFields ports upstream filterOutputFields
// (@better-auth/core/utils/db): it drops only fields declared with
// returned:false and keeps everything else — including keys unknown to the
// schema. Callers pass the model's full field map.
//
// Upstream TypeScript name: filterOutputFields.
func FilterOutputFields(row map[string]any, fields map[string]types.FieldAttribute) map[string]any {
	if len(row) == 0 {
		return row
	}
	out := make(map[string]any, len(row))
	for key, value := range row {
		if name, ok := CanonicalInputKey(key, fields); ok {
			if field := fields[name]; field.Returned != nil && !*field.Returned {
				continue
			}
		}
		out[key] = value
	}
	return out
}

// ExtractAdditionalFieldsFull is the full-schema successor of
// extractAdditionalFields: it keeps every non-core entry except fields the
// full schema marks returned:false (mirroring upstream filterOutputFields,
// which keeps unknown keys). Because it unions — unknown undeclared fields
// pass through — migrating output consumers (rowToSession/rowToUser) from
// the legacy plugin-only allow-list to this helper only ADDS previously
// dropped fields and never strips previously returned ones, except
// returned:false fields which upstream also strips.
func ExtractAdditionalFieldsFull(row map[string]any, fullFields map[string]types.FieldAttribute, isCore func(string) bool) map[string]any {
	if len(row) == 0 {
		return nil
	}
	out := map[string]any{}
	for key, value := range row {
		if value == nil || isCore(key) {
			continue
		}
		if name, ok := CanonicalInputKey(key, fullFields); ok {
			if field := fullFields[name]; field.Returned != nil && !*field.Returned {
				continue
			}
			out[name] = value
			continue
		}
		out[snakeToCamel(key)] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FilterSessionUpdateFieldsFull is the full-schema successor of
// filterSessionUpdateFields (session_extra.go): core session columns stay
// unwritable; known full-schema fields get upstream update semantics
// (input:false rejected when truthy via FIELD_NOT_ALLOWED, validator and
// transform input hooks executed); fields unknown to the full schema are
// dropped, mirroring upstream parseInputData (db/schema.ts) which iterates
// schema fields and never copies unknown data keys. Unknown-only bodies
// therefore yield an empty map and 400 via sessionUpdateFields ("No fields
// to update", update-session.ts:64-74). The returned map uses the body's
// original keys, except physical/snake spellings of known fields, which are
// normalized to logical names. Validators see the raw value; a validator
// rejection surfaces as *FieldParseError with types.ErrValidationError.
func FilterSessionUpdateFieldsFull(body map[string]any, fullFields map[string]types.FieldAttribute) (map[string]any, error) {
	out := make(map[string]any, len(body))
	for key, value := range body {
		if isCoreSessionColumnForFilter(key) {
			continue
		}
		name, ok := CanonicalInputKey(key, fullFields)
		if !ok {
			// Upstream parity (parseInputData): unknown data keys are
			// ignored, never copied. Unknown-only bodies yield an empty
			// map so sessionUpdateFields 400s ("No fields to update").
			continue
		}
		field := fullFields[name]
		if field.Input != nil && !*field.Input {
			if isTruthy(value) {
				return nil, &FieldParseError{
					Code:    types.ErrFieldNotAllowed,
					Field:   name,
					Message: fmt.Sprintf("%s is not allowed to be set", name),
				}
			}
			continue
		}
		if field.Validator != nil && field.Validator.Input != nil && value != nil {
			if err := field.Validator.Input.Validate(value); err != nil {
				return nil, &FieldParseError{
					Code:    types.ErrValidationError,
					Field:   name,
					Message: err.Error(),
				}
			}
		}
		if field.Transform != nil && field.Transform.Input != nil && value != nil {
			transferred, err := field.Transform.Input(value)
			if err != nil {
				return nil, err
			}
			out[name] = transferred
			continue
		}
		out[name] = value
	}
	return out, nil
}

// defaultValueOf evaluates a field's DefaultValue (calling zero-arg func
// factories of any signature like upstream () => new Date() /
// () => Date.now()) or returns the static scalar.
func defaultValueOf(field types.FieldAttribute) any {
	if field.DefaultValue == nil {
		return nil
	}
	if fn, ok := field.DefaultValue.(func() any); ok && fn != nil {
		return fn()
	}
	rv := reflect.ValueOf(field.DefaultValue)
	if rv.Kind() == reflect.Func && rv.Type().NumIn() == 0 && rv.Type().NumOut() == 1 {
		return rv.Call(nil)[0].Interface()
	}
	return field.DefaultValue
}

// isTruthy mirrors the upstream `if (data[key])` gate on input:false
// fields: only truthy values are rejected.
func isTruthy(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case int8:
		return v != 0
	case int16:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case uint:
		return v != 0
	case uint8:
		return v != 0
	case uint16:
		return v != 0
	case uint32:
		return v != 0
	case uint64:
		return v != 0
	case float32:
		return v != 0
	case float64:
		return v != 0
	default:
		return true
	}
}

// isCoreSessionColumnForFilter keeps the core-session unwritable set next to
// this file's full-schema filter so the helper is self-contained for tests
// and future consumers; it mirrors isCoreSessionColumn in session.go (owned
// by the session-route owner — any column added there must be added here).
func isCoreSessionColumnForFilter(key string) bool {
	switch key {
	case "id", "user_id", "userId", "token", "expires_at", "expiresAt", "ip_address", "ipAddress", "user_agent", "userAgent", "active_organization_id", "activeOrganizationId", "active_team_id", "activeTeamId", "created_at", "createdAt", "updated_at", "updatedAt":
		return true
	default:
		return false
	}
}

// fullSessionFields returns the additional-field subset of the full session
// schema for route field processing: plugin-declared session fields unioned
// with the session option additionalFields, option winning on conflict.
// That precedence (core→plugin→options) matches GetAuthTables in
// auth/schema.go; core columns are absent here by construction because both
// Full consumers (ExtractAdditionalFieldsFull, FilterSessionUpdateFieldsFull)
// pre-filter core session columns before consulting the map, so core field
// definitions can never affect the result.
//
// It is intentionally storage-independent: upstream parseSessionInput reads
// getFields(options) regardless of secondary storage, so option/plugin
// validators and transforms execute on update bodies even when the session
// table itself is secondary-stored (where GetAuthTables omits the model for
// migration purposes).
func fullSessionFields(opts types.Options) map[string]types.FieldAttribute {
	out := make(map[string]types.FieldAttribute,
		len(opts.Schema["session"].Fields)+len(opts.Session.Model.AdditionalFields))
	for name, field := range opts.Schema["session"].Fields {
		out[name] = field
	}
	for name, field := range opts.Session.Model.AdditionalFields {
		out[name] = field
	}
	return out
}

// fullUserFields is the user-model counterpart of fullSessionFields:
// plugin-declared user fields unioned with the user option
// additionalFields, option winning on conflict.
func fullUserFields(opts types.Options) map[string]types.FieldAttribute {
	out := make(map[string]types.FieldAttribute,
		len(opts.Schema["user"].Fields)+len(opts.User.Model.AdditionalFields))
	for name, field := range opts.Schema["user"].Fields {
		out[name] = field
	}
	for name, field := range opts.User.Model.AdditionalFields {
		out[name] = field
	}
	return out
}

func extractAdditionalFields(row map[string]any, fields map[string]types.FieldAttribute, isCore func(string) bool) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	out := map[string]any{}
	for key, value := range row {
		if value == nil || isCore(key) {
			continue
		}
		name := snakeToCamel(key)
		field, ok := fields[name]
		if !ok || field.Returned != nil && !*field.Returned {
			continue
		}
		out[name] = value
	}
	return out
}

func snakeToCamel(s string) string {
	var out strings.Builder
	upperNext := false
	for _, r := range s {
		if r == '_' {
			upperNext = true
			continue
		}
		if upperNext && r >= 'a' && r <= 'z' {
			out.WriteRune(r - ('a' - 'A'))
			upperNext = false
			continue
		}
		upperNext = false
		out.WriteRune(r)
	}
	return out.String()
}

// ---------------------------------------------------------------------------
// AUTH-S6-01: explicit full-schema helper APIs for Wave 7 route adoption.
//
// These exported helpers are the migration targets for route handlers still
// on the legacy plugin-only allow-list (opts.Schema + unexported
// fullSessionFields/fullUserFields). They union — never intersect — with
// legacy acceptance so adoption only adds previously dropped fields (except
// returned:false, which upstream also strips). No handlers are rewired here;
// Wave 7 consumes these APIs.
//
// Field maps derive from the single resolved schema (core→plugin→options,
// option winning): plugin-declared fields from opts.Schema unioned with the
// per-model option additionalFields. That is the FullSchema non-core subset:
// callers pre-filter core columns before consulting the map, so core field
// definitions can never affect the result (see fullSessionFields).
// ---------------------------------------------------------------------------

// FullUserFields returns the full-schema user field map for route input/
// output processing: plugin-declared user fields unioned with the user
// option additionalFields, option winning on conflict.
//
// Upstream TypeScript name: getFields (user input/output modes in
// db/schema.ts); this is the Go route-side projection.
func FullUserFields(opts types.Options) map[string]types.FieldAttribute {
	return fullUserFields(opts)
}

// FullSessionFields returns the full-schema session field map for route
// input/output processing.
func FullSessionFields(opts types.Options) map[string]types.FieldAttribute {
	return fullSessionFields(opts)
}

// FullAccountFields returns the full-schema account field map for route
// input/output processing: plugin-declared account fields unioned with the
// account option additionalFields, option winning on conflict. Go-only
// helper (upstream getFields covers user/session/account additionalFields;
// account has no legacy route consumer yet, so this is the Wave 7 target).
func FullAccountFields(opts types.Options) map[string]types.FieldAttribute {
	out := make(map[string]types.FieldAttribute,
		len(opts.Schema["account"].Fields)+len(opts.Account.Model.AdditionalFields))
	for name, field := range opts.Schema["account"].Fields {
		out[name] = field
	}
	for name, field := range opts.Account.Model.AdditionalFields {
		out[name] = field
	}
	return out
}

// FullUserFieldsForOptions is an alias of FullUserFields kept for symmetry
// with cross-package test call sites. Go-only helper.
func FullUserFieldsForOptions(opts types.Options) map[string]types.FieldAttribute {
	return FullUserFields(opts)
}

// ParseUserInputFull parses a user input payload against the provided full
// field map with upstream parseInputData semantics (create vs update).
// Unknown keys are ignored, input:false truthy values rejected, validators
// and transforms executed, defaults applied on create, required enforced on
// create.
//
// Upstream TypeScript name: parseInputData (user projection).
func ParseUserInputFull(data map[string]any, fullFields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	return ParseInputData(data, fullFields, action)
}

// ParseSessionInputFull parses a session input payload against the provided
// full field map.
//
// Upstream TypeScript name: parseInputData (session projection).
func ParseSessionInputFull(data map[string]any, fullFields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	return ParseInputData(data, fullFields, action)
}

// FilterUserOutputFull strips returned:false fields from a user row,
// keeping everything else including unknown keys.
//
// Upstream TypeScript name: filterOutputFields (user projection).
func FilterUserOutputFull(row map[string]any, fullFields map[string]types.FieldAttribute) map[string]any {
	return FilterOutputFields(row, fullFields)
}

// FilterSessionOutputFull strips returned:false fields from a session row.
//
// Upstream TypeScript name: filterOutputFields (session projection).
func FilterSessionOutputFull(row map[string]any, fullFields map[string]types.FieldAttribute) map[string]any {
	return FilterOutputFields(row, fullFields)
}

// ValidateUserInfoRedirectURL builds the browser-flow redirect for a
// ValidateUserInfo gate rejection: baseURL with ?error=<code>&
// error_description=<msg>, appending with & when the base already carries a
// query string. It mirrors upstream redirectOnError for the gate codes;
// programmatic flows surface NewValidateUserInfoError (403) instead.
//
// Upstream TypeScript name: redirectOnError (validateUserInfo application).
func ValidateUserInfoRedirectURL(baseURL, code, description string) string {
	params := url.Values{}
	params.Set("error", code)
	if description != "" {
		params.Set("error_description", description)
	}
	encoded := params.Encode()
	var fragment string
	base := baseURL
	if i := strings.Index(base, "#"); i >= 0 {
		fragment = base[i:]
		base = base[:i]
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + encoded + fragment
}

// NewValidateUserInfoError builds the programmatic-flow 403 error for a
// ValidateUserInfo gate rejection, carrying the gate code verbatim with the
// description (or code) as the message. Browser flows use
// ValidateUserInfoRedirectURL instead.
//
// Upstream TypeScript name: the APIError("FORBIDDEN", { code, message })
// thrown by assertValidUserInfo.
func NewValidateUserInfoError(code, description string) types.HttpError {
	msg := description
	if msg == "" {
		msg = code
	}
	return types.HttpError{Code: code, Message: msg, Status: 403}
}
