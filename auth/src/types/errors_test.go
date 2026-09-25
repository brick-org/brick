package types

import "testing"

// allErrorCodes lists every BASE_ERROR_CODES key from
var allErrorCodes = []struct {
	name  string
	value string
}{
	{"USER_NOT_FOUND", ErrUserNotFound},
	{"FAILED_TO_CREATE_USER", ErrFailedToCreateUser},
	{"FAILED_TO_CREATE_SESSION", ErrFailedToCreateSession},
	{"FAILED_TO_UPDATE_USER", ErrFailedToUpdateUser},
	{"FAILED_TO_GET_SESSION", ErrFailedToGetSession},
	{"INVALID_PASSWORD", ErrInvalidPassword},
	{"INVALID_EMAIL", ErrInvalidEmail},
	{"INVALID_EMAIL_OR_PASSWORD", ErrInvalidEmailOrPassword},
	{"INVALID_USER", ErrInvalidUser},
	{"SOCIAL_ACCOUNT_ALREADY_LINKED", ErrSocialAccountAlreadyLinked},
	{"PROVIDER_NOT_FOUND", ErrProviderNotFound},
	{"INVALID_TOKEN", ErrInvalidToken},
	{"TOKEN_EXPIRED", ErrTokenExpired},
	{"ID_TOKEN_NOT_SUPPORTED", ErrIDTokenNotSupported},
	{"FAILED_TO_GET_USER_INFO", ErrFailedToGetUserInfo},
	{"USER_EMAIL_NOT_FOUND", ErrUserEmailNotFound},
	{"EMAIL_NOT_VERIFIED", ErrEmailNotVerified},
	{"PASSWORD_TOO_SHORT", ErrPasswordTooShort},
	{"PASSWORD_TOO_LONG", ErrPasswordTooLong},
	{"USER_ALREADY_EXISTS", ErrUserAlreadyExists},
	{"USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", ErrUserAlreadyExistsUseAnotherEmail},
	{"EMAIL_CAN_NOT_BE_UPDATED", ErrEmailCanNotBeUpdated},
	{"CHANGE_EMAIL_DISABLED", ErrChangeEmailDisabled},
	{"CREDENTIAL_ACCOUNT_NOT_FOUND", ErrCredentialAccountNotFound},
	{"SESSION_EXPIRED", ErrSessionExpired},
	{"FAILED_TO_UNLINK_LAST_ACCOUNT", ErrFailedToUnlinkLastAccount},
	{"ACCOUNT_NOT_FOUND", ErrAccountNotFound},
	{"USER_ALREADY_HAS_PASSWORD", ErrUserAlreadyHasPassword},
	{"CROSS_SITE_NAVIGATION_LOGIN_BLOCKED", ErrCrossSiteNavigationLoginBlocked},
	{"VERIFICATION_EMAIL_NOT_ENABLED", ErrVerificationEmailNotEnabled},
	{"EMAIL_ALREADY_VERIFIED", ErrEmailAlreadyVerified},
	{"EMAIL_MISMATCH", ErrEmailMismatch},
	{"SESSION_NOT_FRESH", ErrSessionNotFresh},
	{"LINKED_ACCOUNT_ALREADY_EXISTS", ErrLinkedAccountAlreadyExists},
	{"INVALID_ORIGIN", ErrInvalidOrigin},
	{"INVALID_CALLBACK_URL", ErrInvalidCallbackURL},
	{"INVALID_REDIRECT_URL", ErrInvalidRedirectURL},
	{"INVALID_ERROR_CALLBACK_URL", ErrInvalidErrorCallbackURL},
	{"INVALID_NEW_USER_CALLBACK_URL", ErrInvalidNewUserCallbackURL},
	{"MISSING_OR_NULL_ORIGIN", ErrMissingOrNullOrigin},
	{"CALLBACK_URL_REQUIRED", ErrCallbackURLRequired},
	{"FAILED_TO_CREATE_VERIFICATION", ErrFailedToCreateVerification},
	{"FIELD_NOT_ALLOWED", ErrFieldNotAllowed},
	{"ASYNC_VALIDATION_NOT_SUPPORTED", ErrAsyncValidationNotSupported},
	{"VALIDATION_ERROR", ErrValidationError},
	{"MISSING_FIELD", ErrMissingField},
	{"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED", ErrMethodNotAllowedDeferSessionRequired},
	{"BODY_MUST_BE_AN_OBJECT", ErrBodyMustBeAnObject},
	{"PASSWORD_ALREADY_SET", ErrPasswordAlreadySet},
}

func TestErrorCodesMatchUpstreamKeys(t *testing.T) {
	for _, code := range allErrorCodes {
		if code.value != code.name {
			t.Errorf("error code constant for %s has value %q, want exact upstream key", code.name, code.value)
		}
	}
}

func TestErrorCodesNonEmptyAndUnique(t *testing.T) {
	seen := map[string]string{}
	for _, code := range allErrorCodes {
		if code.value == "" {
			t.Errorf("error code %s is empty", code.name)
		}
		if prev, dup := seen[code.value]; dup {
			t.Errorf("error code value %q shared by %s and %s", code.value, prev, code.name)
		}
		seen[code.value] = code.name
	}
}
