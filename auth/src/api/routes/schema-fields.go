package routes

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// a non-empty declared map as an allow-list over plugin-only fields. The
// option additionalFields) with upstream input/output semantics. Output
// helpers union — never intersect — with legacy acceptance: fields unknown
// to the full schema keep the passthrough so migrating output consumers
// never newly strip previously returned fields. The session-update input
// filter instead drops unknown keys per upstream parseInputData, so
// unknown-only bodies 400 ("No fields to update").

// FieldParseError carries a Better Auth error code for input parsing
type FieldParseError struct {
	Code string
	// Field is the logical field that failed.
	Field string
	Message string
}

func (e *FieldParseError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// CanonicalInputKey resolves a body/row key to its logical field name,
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
// never copied), enforces input:false (default substituted on create, truthy
// Upstream TypeScript name: parseInputData.
func ParseInputData(data map[string]any, fields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	if action == "" {
		action = "create"
	}
	parsed := make(map[string]any)
	// Canonicalize incoming keys once so physical spellings match logical
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
// dropped fields and never strips previously returned ones, except
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
// schema fields and never copies unknown data keys. Unknown-only bodies
// therefore yield an empty map and 400 via sessionUpdateFields ("No fields
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

// factories of any signature like upstream () => new Date() /
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

// this file's full-schema filter so the helper is self-contained for tests
// by the session-route owner — any column added there must be added here).
func isCoreSessionColumnForFilter(key string) bool {
	switch key {
	case "id", "user_id", "userId", "token", "expires_at", "expiresAt", "ip_address", "ipAddress", "user_agent", "userAgent", "active_organization_id", "activeOrganizationId", "active_team_id", "activeTeamId", "created_at", "createdAt", "updated_at", "updatedAt":
		return true
	default:
		return false
	}
}

// pre-filter core session columns before consulting the map, so core field
// definitions can never affect the result.
// It is intentionally storage-independent: upstream parseSessionInput reads
// getFields(options) regardless of secondary storage, so option/plugin
// validators and transforms execute on update bodies even when the session
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

// on the legacy plugin-only allow-list (opts.Schema + unexported
// fullSessionFields/fullUserFields). They union — never intersect — with
// legacy acceptance so adoption only adds previously dropped fields (except
// callers pre-filter core columns before consulting the map, so core field
// definitions can never affect the result (see fullSessionFields).

// FullUserFields returns the full-schema user field map for route input/
// Upstream TypeScript name: getFields (user input/output modes in
func FullUserFields(opts types.Options) map[string]types.FieldAttribute {
	return fullUserFields(opts)
}

// FullSessionFields returns the full-schema session field map for route
func FullSessionFields(opts types.Options) map[string]types.FieldAttribute {
	return fullSessionFields(opts)
}

// FullAccountFields returns the full-schema account field map for route
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
func FullUserFieldsForOptions(opts types.Options) map[string]types.FieldAttribute {
	return FullUserFields(opts)
}

// ParseUserInputFull parses a user input payload against the provided full
// Upstream TypeScript name: parseInputData (user projection).
func ParseUserInputFull(data map[string]any, fullFields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	return ParseInputData(data, fullFields, action)
}

// ParseSessionInputFull parses a session input payload against the provided
// Upstream TypeScript name: parseInputData (session projection).
func ParseSessionInputFull(data map[string]any, fullFields map[string]types.FieldAttribute, action string) (map[string]any, error) {
	return ParseInputData(data, fullFields, action)
}

// FilterUserOutputFull strips returned:false fields from a user row,
// Upstream TypeScript name: filterOutputFields (user projection).
func FilterUserOutputFull(row map[string]any, fullFields map[string]types.FieldAttribute) map[string]any {
	return FilterOutputFields(row, fullFields)
}

// FilterSessionOutputFull strips returned:false fields from a session row.
// Upstream TypeScript name: filterOutputFields (session projection).
func FilterSessionOutputFull(row map[string]any, fullFields map[string]types.FieldAttribute) map[string]any {
	return FilterOutputFields(row, fullFields)
}

// ValidateUserInfoRedirectURL builds the browser-flow redirect for a
// programmatic flows surface NewValidateUserInfoError (403) instead.
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
// Upstream TypeScript name: the APIError("FORBIDDEN", { code, message })
func NewValidateUserInfoError(code, description string) types.HttpError {
	msg := description
	if msg == "" {
		msg = code
	}
	return types.HttpError{Code: code, Message: msg, Status: 403}
}
