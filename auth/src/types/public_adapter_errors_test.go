package types

import (
	"context"
	"net/http"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// TestAdapterReexportCompleteness pins that every exported symbol in
// auth/db/adapter-base.go is reachable via this package with identical values.
func TestAdapterReexportCompleteness(t *testing.T) {
	if DefaultFindManyLimit != 100 {
		t.Errorf("DefaultFindManyLimit = %d, want 100", DefaultFindManyLimit)
	}
	if DefaultFindManyLimit != authdb.DefaultFindManyLimit {
		t.Errorf("DefaultFindManyLimit = %d, want authdb.DefaultFindManyLimit", DefaultFindManyLimit)
	}
	ops := map[string]struct {
		got  Operator
		want authdb.Operator
	}{
		"OpEq": {OpEq, authdb.OpEq}, "OpNe": {OpNe, authdb.OpNe},
		"OpLt": {OpLt, authdb.OpLt}, "OpLte": {OpLte, authdb.OpLte},
		"OpGt": {OpGt, authdb.OpGt}, "OpGte": {OpGte, authdb.OpGte},
		"OpIn": {OpIn, authdb.OpIn}, "OpNotIn": {OpNotIn, authdb.OpNotIn},
		"OpContains":   {OpContains, authdb.OpContains},
		"OpStartsWith": {OpStartsWith, authdb.OpStartsWith},
		"OpEndsWith":   {OpEndsWith, authdb.OpEndsWith},
		"Eq":           {Eq, authdb.Eq}, "Ne": {Ne, authdb.Ne},
		"Lt": {Lt, authdb.Lt}, "Lte": {Lte, authdb.Lte},
		"Gt": {Gt, authdb.Gt}, "Gte": {Gte, authdb.Gte},
		"In": {In, authdb.In}, "NotIn": {NotIn, authdb.NotIn},
		"Contains":   {Contains, authdb.Contains},
		"StartsWith": {StartsWith, authdb.StartsWith},
		"EndsWith":   {EndsWith, authdb.EndsWith},
	}
	for name, op := range ops {
		if op.got != op.want {
			t.Errorf("%s = %q, want %q", name, op.got, op.want)
		}
	}
	var _ WhereOperator = OpEq
	if string(Eq) != "eq" || string(NotIn) != "not_in" || string(StartsWith) != "starts_with" {
		t.Error("short operator alias values changed")
	}

	if ConnectorAND != "AND" || ConnectorOR != "OR" {
		t.Error("connector constants changed")
	}
	var c Connector = Connector(ConnectorOR)
	if c.Normalize() != Connector(ConnectorOR) || !c.IsValid() {
		t.Error("Connector kind methods not reachable via alias")
	}
	if NormalizeConnector("or") != Connector(ConnectorOR) || NormalizeConnector("bogus") != Connector(ConnectorAND) {
		t.Error("NormalizeConnector behavior changed")
	}

	if WhereModeSensitive != "sensitive" || WhereModeInsensitive != "insensitive" {
		t.Error("where mode literals changed")
	}
	var m WhereMode = WhereModeInsensitiveKind
	if m.Normalize() != WhereModeInsensitiveKind || !m.IsValid() {
		t.Error("WhereMode kind methods not reachable via alias")
	}
	if NormalizeWhereMode("INSENSITIVE") != WhereModeInsensitiveKind ||
		NormalizeWhereMode("") != WhereModeSensitiveKind {
		t.Error("NormalizeWhereMode behavior changed")
	}

	if SortDirectionAsc != "asc" || SortDirectionDesc != "desc" {
		t.Error("sort direction constants changed")
	}
	var d SortDirection = SortDirection(SortDirectionDesc)
	if d.Normalize() != SortDirection(SortDirectionDesc) || !d.IsValid() {
		t.Error("SortDirection kind methods not reachable via alias")
	}
	if NormalizeSortDirection("DESC") != SortDirection(SortDirectionDesc) ||
		NormalizeSortDirection("") != SortDirection(SortDirectionAsc) {
		t.Error("NormalizeSortDirection behavior changed")
	}

	var cfg AdapterConfig
	if cfg.ModelName("user") != "user" || cfg.FieldName("user", "email") != "email" {
		t.Error("AdapterConfig helpers not reachable via alias")
	}
	var _ Where = Where{}
	var _ SortBy = SortBy{}
	var _ Adapter = stubAdapter{}
}

// stubAdapter proves auth/db.Adapter implementations satisfy types.Adapter.
type stubAdapter struct{ authdb.Adapter }

var _ = context.Background

// TestErrorCodeFullSetPin pins the exact 49-code upstream set: order length,
// map coverage with no extras, and Code fields matching keys.
func TestErrorCodeFullSetPin(t *testing.T) {
	if len(BaseErrorCodeOrder) != 49 {
		t.Fatalf("len(BaseErrorCodeOrder) = %d, want 49", len(BaseErrorCodeOrder))
	}
	if len(BaseErrorMessages) != 49 || len(BaseErrorCodes) != 49 {
		t.Fatalf("map sizes = %d/%d, want 49/49", len(BaseErrorMessages), len(BaseErrorCodes))
	}
	for _, code := range BaseErrorCodeOrder {
		msg, ok := BaseErrorMessages[code]
		if !ok || msg == "" {
			t.Errorf("missing message for %s", code)
		}
		obj, ok := BaseErrorCodes[code]
		if !ok {
			t.Errorf("missing RawError for %s", code)
			continue
		}
		if obj.Code != code || obj.Message != msg {
			t.Errorf("BaseErrorCodes[%q] = %+v, want matching Code/Message", code, obj)
		}
	}
	for code := range BaseErrorMessages {
		found := false
		for _, ordered := range BaseErrorCodeOrder {
			if ordered == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("BaseErrorMessages has extra code %s outside BaseErrorCodeOrder", code)
		}
	}
}

// TestStatusForCodeSpotChecks pins the canonical upstream status per class.
func TestStatusForCodeSpotChecks(t *testing.T) {
	cases := map[string]int{
		// 404: majority-NOT_FOUND throw sites upstream.
		ErrUserNotFound: http.StatusNotFound, ErrProviderNotFound: http.StatusNotFound,
		ErrIDTokenNotSupported: http.StatusNotFound,
		// 401: majority-UNAUTHORIZED throw sites upstream.
		ErrFailedToGetSession: http.StatusUnauthorized, ErrInvalidEmailOrPassword: http.StatusUnauthorized,
		ErrInvalidToken: http.StatusUnauthorized, ErrFailedToGetUserInfo: http.StatusUnauthorized,
		ErrUserEmailNotFound: http.StatusUnauthorized, ErrTokenExpired: http.StatusUnauthorized,
		ErrInvalidUser: http.StatusUnauthorized,
		// 403: FORBIDDEN throw sites (origin-check middleware etc.).
		ErrEmailNotVerified: http.StatusForbidden, ErrCrossSiteNavigationLoginBlocked: http.StatusForbidden,
		ErrSessionNotFresh: http.StatusForbidden, ErrInvalidOrigin: http.StatusForbidden,
		ErrInvalidCallbackURL: http.StatusForbidden, ErrInvalidRedirectURL: http.StatusForbidden,
		ErrInvalidErrorCallbackURL: http.StatusForbidden, ErrInvalidNewUserCallbackURL: http.StatusForbidden,
		ErrMissingOrNullOrigin: http.StatusForbidden,
		// 409.
		ErrSocialAccountAlreadyLinked: http.StatusConflict, ErrUserAlreadyExists: http.StatusConflict,
		ErrLinkedAccountAlreadyExists: http.StatusConflict,
		// 422.
		ErrFailedToCreateUser:               http.StatusUnprocessableEntity,
		ErrUserAlreadyExistsUseAnotherEmail: http.StatusUnprocessableEntity,
		// 405.
		ErrMethodNotAllowedDeferSessionRequired: http.StatusMethodNotAllowed,
		// 500.
		ErrFailedToCreateSession: http.StatusInternalServerError, ErrFailedToUpdateUser: http.StatusInternalServerError,
		ErrAsyncValidationNotSupported: http.StatusInternalServerError,
		ErrFailedToCreateVerification:  http.StatusInternalServerError,
		// 400 default class spot-checks.
		ErrInvalidPassword: http.StatusBadRequest, ErrInvalidEmail: http.StatusBadRequest,
		ErrPasswordTooShort: http.StatusBadRequest, ErrSessionExpired: http.StatusBadRequest,
		ErrAccountNotFound: http.StatusBadRequest, ErrValidationError: http.StatusBadRequest,
		ErrMissingField: http.StatusBadRequest, ErrBodyMustBeAnObject: http.StatusBadRequest,
		ErrPasswordAlreadySet: http.StatusBadRequest, ErrCallbackURLRequired: http.StatusBadRequest,
	}
	for code, want := range cases {
		if got := StatusForCode(code); got != want {
			t.Errorf("StatusForCode(%s) = %d, want %d", code, got, want)
		}
	}
	// Every pinned code maps to a 4xx/5xx status.
	for _, code := range BaseErrorCodeOrder {
		if s := StatusForCode(code); s < 400 || s > 599 {
			t.Errorf("StatusForCode(%s) = %d, want error status", code, s)
		}
	}
	if got := StatusForCode("NO_SUCH_CODE"); got != http.StatusInternalServerError {
		t.Errorf("StatusForCode(unknown) = %d, want 500", got)
	}
}

func TestNewHttpError(t *testing.T) {
	e := NewHttpError(ErrInvalidEmailOrPassword)
	if e.Code != ErrInvalidEmailOrPassword || e.Message != BaseErrorMessages[ErrInvalidEmailOrPassword] {
		t.Errorf("NewHttpError code/message = %+v", e)
	}
	if e.Status != http.StatusUnauthorized {
		t.Errorf("NewHttpError status = %d, want 401", e.Status)
	}
	if e.Error() != e.Message || e.String() != e.Code {
		t.Errorf("HttpError Error()/String() = %q/%q", e.Error(), e.String())
	}
	unknown := NewHttpError("NO_SUCH_CODE")
	if unknown.Status != http.StatusInternalServerError {
		t.Errorf("NewHttpError(unknown) status = %d, want 500", unknown.Status)
	}
	var _ error = HttpError{}
}
