package types

import "net/http"

// File boundary: auth/src/types/api.go, mirroring the upstream
// src/types/api.ts boundary.
//
// Content note: upstream api.ts is type-inference only (InferAPI over
// endpoints) with no Go equivalent. This file carries the BASE_ERROR_CODES
// surface (upstream @better-auth/core error codes) plus the HttpError
// metadata helpers, moved unchanged from the former types/errors.go per
// SOURCE_LAYOUT_MOVE_LIST.md (types/errors.go -> types/api.go).

// RawError mirrors better-auth's RawError ({ code, message }).
//
// Upstream TypeScript name: RawError (packages/core/src/utils/error-codes.ts).
// Code is the UPPER_SNAKE key (e.g. "USER_NOT_FOUND"); Message is the
// human-readable string from BASE_ERROR_CODES. Use String() or Code to get
// the key; the message is for display only.
type RawError struct {
	Code    string
	Message string
}

// String returns the error code key, mirroring upstream's toString() => key.
func (e RawError) String() string { return e.Code }

// HttpError is the error-object shape carrying HTTP metadata: the upstream
// { code, message } pair plus the HTTP status the error maps to.
//
// Upstream, Better Auth throws APIError(status, { code, message }) where
// status is a better-call status name ("BAD_REQUEST", "UNAUTHORIZED",
// "FORBIDDEN", "NOT_FOUND", "CONFLICT", "UNPROCESSABLE_ENTITY",
// "METHOD_NOT_ALLOWED", "INTERNAL_SERVER_ERROR", ...) chosen at each throw
// site; Status is that status as a numeric code (see StatusForCode). HTTP
// handlers (e.g. huma mappings) should use Status as the response status and
// Code/Message as the body so error responses stay pinned to upstream.
type HttpError struct {
	Code    string
	Message string
	Status  int
}

// Error implements the error interface, returning the human-readable message.
func (e HttpError) Error() string { return e.Message }

// String returns the error code key, mirroring RawError's toString() => key.
func (e HttpError) String() string { return e.Code }

// StatusForCode returns the canonical upstream HTTP status for a
// BASE_ERROR_CODES key.
//
// Upstream pins only the { code, message } pair per key; the status varies by
// throw site (e.g. USER_NOT_FOUND is thrown as NOT_FOUND, BAD_REQUEST, and
// UNAUTHORIZED across routes). This maps each key to its most common
// upstream status, surveyed from
// vendor/better-auth/packages/{better-auth/src,core/src} (v1.7.5):
//   - multi-status codes resolve to the majority throw-site status
//     (USER_NOT_FOUND -> 404, INVALID_TOKEN -> 401, FAILED_TO_GET_USER_INFO
//     -> 401, FAILED_TO_CREATE_USER -> 422, FAILED_TO_CREATE_SESSION -> 500)
//   - keys with no base throw site use a semantic default, marked below:
//     USER_ALREADY_EXISTS -> 409, USER_ALREADY_HAS_PASSWORD -> 400,
//     LINKED_ACCOUNT_ALREADY_EXISTS -> 409, FAILED_TO_CREATE_VERIFICATION
//     -> 500 (its message is thrown as INTERNAL_SERVER_ERROR in
//     oauth2/state.ts)
//
// Unknown codes return 500. Callers must not depend on statuses for codes
// outside BaseErrorCodeOrder.
func StatusForCode(code string) int {
	switch code {
	case ErrUserNotFound,
		ErrProviderNotFound,
		ErrIDTokenNotSupported:
		return http.StatusNotFound
	case ErrFailedToGetSession,
		ErrInvalidEmailOrPassword,
		ErrInvalidToken,
		ErrFailedToGetUserInfo,
		ErrUserEmailNotFound,
		ErrTokenExpired,
		ErrInvalidUser:
		return http.StatusUnauthorized
	case ErrEmailNotVerified,
		ErrCrossSiteNavigationLoginBlocked,
		ErrSessionNotFresh,
		ErrInvalidOrigin,
		ErrInvalidCallbackURL,
		ErrInvalidRedirectURL,
		ErrInvalidErrorCallbackURL,
		ErrInvalidNewUserCallbackURL,
		ErrMissingOrNullOrigin:
		return http.StatusForbidden
	case ErrSocialAccountAlreadyLinked,
		ErrUserAlreadyExists,
		ErrLinkedAccountAlreadyExists:
		return http.StatusConflict
	case ErrFailedToCreateUser,
		ErrUserAlreadyExistsUseAnotherEmail:
		return http.StatusUnprocessableEntity
	case ErrMethodNotAllowedDeferSessionRequired:
		return http.StatusMethodNotAllowed
	case ErrFailedToCreateSession,
		ErrFailedToUpdateUser,
		ErrAsyncValidationNotSupported,
		ErrFailedToCreateVerification:
		return http.StatusInternalServerError
	default:
		if _, ok := BaseErrorMessages[code]; ok {
			return http.StatusBadRequest
		}
		return http.StatusInternalServerError
	}
}

// NewHttpError builds the HttpError for a BASE_ERROR_CODES key, using the
// pinned message from BaseErrorMessages and the canonical status from
// StatusForCode. Unknown codes yield a 500 with the code as the message.
func NewHttpError(code string) HttpError {
	msg, ok := BaseErrorMessages[code]
	if !ok {
		return HttpError{Code: code, Message: code, Status: http.StatusInternalServerError}
	}
	return HttpError{Code: code, Message: msg, Status: StatusForCode(code)}
}

// BaseErrorMessages holds every BASE_ERROR_CODES message from
// vendor/better-auth/packages/core/src/error/codes.ts (v1.7.5) in upstream
// order, keyed by code. Use BaseErrorCodes for the full {code,message}
// objects; this map is for message-only readers.
var BaseErrorMessages = map[string]string{
	"USER_NOT_FOUND":                            "User not found",
	"FAILED_TO_CREATE_USER":                     "Failed to create user",
	"FAILED_TO_CREATE_SESSION":                  "Failed to create session",
	"FAILED_TO_UPDATE_USER":                     "Failed to update user",
	"FAILED_TO_GET_SESSION":                     "Failed to get session",
	"INVALID_PASSWORD":                          "Invalid password",
	"INVALID_EMAIL":                             "Invalid email",
	"INVALID_EMAIL_OR_PASSWORD":                 "Invalid email or password",
	"INVALID_USER":                              "Invalid user",
	"SOCIAL_ACCOUNT_ALREADY_LINKED":             "Social account already linked",
	"PROVIDER_NOT_FOUND":                        "Provider not found",
	"INVALID_TOKEN":                             "Invalid token",
	"TOKEN_EXPIRED":                             "Token expired",
	"ID_TOKEN_NOT_SUPPORTED":                    "id_token not supported",
	"FAILED_TO_GET_USER_INFO":                   "Failed to get user info",
	"USER_EMAIL_NOT_FOUND":                      "User email not found",
	"EMAIL_NOT_VERIFIED":                        "Email not verified",
	"PASSWORD_TOO_SHORT":                        "Password too short",
	"PASSWORD_TOO_LONG":                         "Password too long",
	"USER_ALREADY_EXISTS":                       "User already exists.",
	"USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL":     "User already exists. Use another email.",
	"EMAIL_CAN_NOT_BE_UPDATED":                  "Email can not be updated",
	"CHANGE_EMAIL_DISABLED":                     "Change email is disabled",
	"CREDENTIAL_ACCOUNT_NOT_FOUND":              "Credential account not found",
	"SESSION_EXPIRED":                           "Session expired. Re-authenticate to perform this action.",
	"FAILED_TO_UNLINK_LAST_ACCOUNT":             "You can't unlink your last account",
	"ACCOUNT_NOT_FOUND":                         "Account not found",
	"USER_ALREADY_HAS_PASSWORD":                 "User already has a password. Provide that to delete the account.",
	"CROSS_SITE_NAVIGATION_LOGIN_BLOCKED":       "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
	"VERIFICATION_EMAIL_NOT_ENABLED":            "Verification email isn't enabled",
	"EMAIL_ALREADY_VERIFIED":                    "Email is already verified",
	"EMAIL_MISMATCH":                            "Email mismatch",
	"SESSION_NOT_FRESH":                         "Session is not fresh",
	"LINKED_ACCOUNT_ALREADY_EXISTS":             "Linked account already exists",
	"INVALID_ORIGIN":                            "Invalid origin",
	"INVALID_CALLBACK_URL":                      "Invalid callbackURL",
	"INVALID_REDIRECT_URL":                      "Invalid redirectURL",
	"INVALID_ERROR_CALLBACK_URL":                "Invalid errorCallbackURL",
	"INVALID_NEW_USER_CALLBACK_URL":             "Invalid newUserCallbackURL",
	"MISSING_OR_NULL_ORIGIN":                    "Missing or null Origin",
	"CALLBACK_URL_REQUIRED":                     "callbackURL is required",
	"FAILED_TO_CREATE_VERIFICATION":             "Unable to create verification",
	"FIELD_NOT_ALLOWED":                         "Field not allowed to be set",
	"ASYNC_VALIDATION_NOT_SUPPORTED":            "Async validation is not supported",
	"VALIDATION_ERROR":                          "Validation Error",
	"MISSING_FIELD":                             "Field is required",
	"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED": "POST method requires deferSessionRefresh to be enabled in session config",
	"BODY_MUST_BE_AN_OBJECT":                    "Body must be an object",
	"PASSWORD_ALREADY_SET":                      "User already has a password set",
}

// BaseErrorCodeOrder lists every BASE_ERROR_CODES key in upstream definition
// order (vendor/.../error/codes.ts). Use it when merging plugin and base
// codes so BASE entries apply last, mirroring
// `$ERROR_CODES: { ...pluginCodes, ...BASE_ERROR_CODES }`.
var BaseErrorCodeOrder = []string{
	"USER_NOT_FOUND",
	"FAILED_TO_CREATE_USER",
	"FAILED_TO_CREATE_SESSION",
	"FAILED_TO_UPDATE_USER",
	"FAILED_TO_GET_SESSION",
	"INVALID_PASSWORD",
	"INVALID_EMAIL",
	"INVALID_EMAIL_OR_PASSWORD",
	"INVALID_USER",
	"SOCIAL_ACCOUNT_ALREADY_LINKED",
	"PROVIDER_NOT_FOUND",
	"INVALID_TOKEN",
	"TOKEN_EXPIRED",
	"ID_TOKEN_NOT_SUPPORTED",
	"FAILED_TO_GET_USER_INFO",
	"USER_EMAIL_NOT_FOUND",
	"EMAIL_NOT_VERIFIED",
	"PASSWORD_TOO_SHORT",
	"PASSWORD_TOO_LONG",
	"USER_ALREADY_EXISTS",
	"USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
	"EMAIL_CAN_NOT_BE_UPDATED",
	"CHANGE_EMAIL_DISABLED",
	"CREDENTIAL_ACCOUNT_NOT_FOUND",
	"SESSION_EXPIRED",
	"FAILED_TO_UNLINK_LAST_ACCOUNT",
	"ACCOUNT_NOT_FOUND",
	"USER_ALREADY_HAS_PASSWORD",
	"CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
	"VERIFICATION_EMAIL_NOT_ENABLED",
	"EMAIL_ALREADY_VERIFIED",
	"EMAIL_MISMATCH",
	"SESSION_NOT_FRESH",
	"LINKED_ACCOUNT_ALREADY_EXISTS",
	"INVALID_ORIGIN",
	"INVALID_CALLBACK_URL",
	"INVALID_REDIRECT_URL",
	"INVALID_ERROR_CALLBACK_URL",
	"INVALID_NEW_USER_CALLBACK_URL",
	"MISSING_OR_NULL_ORIGIN",
	"CALLBACK_URL_REQUIRED",
	"FAILED_TO_CREATE_VERIFICATION",
	"FIELD_NOT_ALLOWED",
	"ASYNC_VALIDATION_NOT_SUPPORTED",
	"VALIDATION_ERROR",
	"MISSING_FIELD",
	"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
	"BODY_MUST_BE_AN_OBJECT",
	"PASSWORD_ALREADY_SET",
}

// BaseErrorCodes holds every BASE_ERROR_CODES entry as RawError objects in
// upstream order (see BaseErrorCodeOrder for the order). Keys and Code
// fields are the exact upstream keys, pinned by types/errors_test.go.
var BaseErrorCodes = func() map[string]RawError {
	out := make(map[string]RawError, len(BaseErrorCodeOrder))
	for _, code := range BaseErrorCodeOrder {
		out[code] = RawError{Code: code, Message: BaseErrorMessages[code]}
	}
	return out
}()

// Error code constants mirroring better-auth BASE_ERROR_CODES.
// source: vendor/better-auth/packages/core/src/error/codes.ts
const (
	ErrUserNotFound                         = "USER_NOT_FOUND"
	ErrFailedToCreateUser                   = "FAILED_TO_CREATE_USER"
	ErrFailedToCreateSession                = "FAILED_TO_CREATE_SESSION"
	ErrFailedToUpdateUser                   = "FAILED_TO_UPDATE_USER"
	ErrFailedToGetSession                   = "FAILED_TO_GET_SESSION"
	ErrInvalidPassword                      = "INVALID_PASSWORD"
	ErrInvalidEmail                         = "INVALID_EMAIL"
	ErrInvalidEmailOrPassword               = "INVALID_EMAIL_OR_PASSWORD"
	ErrInvalidUser                          = "INVALID_USER"
	ErrSocialAccountAlreadyLinked           = "SOCIAL_ACCOUNT_ALREADY_LINKED"
	ErrProviderNotFound                     = "PROVIDER_NOT_FOUND"
	ErrInvalidToken                         = "INVALID_TOKEN"
	ErrTokenExpired                         = "TOKEN_EXPIRED"
	ErrIDTokenNotSupported                  = "ID_TOKEN_NOT_SUPPORTED"
	ErrFailedToGetUserInfo                  = "FAILED_TO_GET_USER_INFO"
	ErrUserEmailNotFound                    = "USER_EMAIL_NOT_FOUND"
	ErrEmailNotVerified                     = "EMAIL_NOT_VERIFIED"
	ErrPasswordTooShort                     = "PASSWORD_TOO_SHORT"
	ErrPasswordTooLong                      = "PASSWORD_TOO_LONG"
	ErrUserAlreadyExists                    = "USER_ALREADY_EXISTS"
	ErrUserAlreadyExistsUseAnotherEmail     = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	ErrEmailCanNotBeUpdated                 = "EMAIL_CAN_NOT_BE_UPDATED"
	ErrChangeEmailDisabled                  = "CHANGE_EMAIL_DISABLED"
	ErrCredentialAccountNotFound            = "CREDENTIAL_ACCOUNT_NOT_FOUND"
	ErrSessionExpired                       = "SESSION_EXPIRED"
	ErrFailedToUnlinkLastAccount            = "FAILED_TO_UNLINK_LAST_ACCOUNT"
	ErrAccountNotFound                      = "ACCOUNT_NOT_FOUND"
	ErrUserAlreadyHasPassword               = "USER_ALREADY_HAS_PASSWORD"
	ErrCrossSiteNavigationLoginBlocked      = "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"
	ErrVerificationEmailNotEnabled          = "VERIFICATION_EMAIL_NOT_ENABLED"
	ErrEmailAlreadyVerified                 = "EMAIL_ALREADY_VERIFIED"
	ErrEmailMismatch                        = "EMAIL_MISMATCH"
	ErrSessionNotFresh                      = "SESSION_NOT_FRESH"
	ErrLinkedAccountAlreadyExists           = "LINKED_ACCOUNT_ALREADY_EXISTS"
	ErrInvalidOrigin                        = "INVALID_ORIGIN"
	ErrInvalidCallbackURL                   = "INVALID_CALLBACK_URL"
	ErrInvalidRedirectURL                   = "INVALID_REDIRECT_URL"
	ErrInvalidErrorCallbackURL              = "INVALID_ERROR_CALLBACK_URL"
	ErrInvalidNewUserCallbackURL            = "INVALID_NEW_USER_CALLBACK_URL"
	ErrMissingOrNullOrigin                  = "MISSING_OR_NULL_ORIGIN"
	ErrCallbackURLRequired                  = "CALLBACK_URL_REQUIRED"
	ErrFailedToCreateVerification           = "FAILED_TO_CREATE_VERIFICATION"
	ErrFieldNotAllowed                      = "FIELD_NOT_ALLOWED"
	ErrAsyncValidationNotSupported          = "ASYNC_VALIDATION_NOT_SUPPORTED"
	ErrValidationError                      = "VALIDATION_ERROR"
	ErrMissingField                         = "MISSING_FIELD"
	ErrMethodNotAllowedDeferSessionRequired = "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED"
	ErrBodyMustBeAnObject                   = "BODY_MUST_BE_AN_OBJECT"
	ErrPasswordAlreadySet                   = "PASSWORD_ALREADY_SET"
)
