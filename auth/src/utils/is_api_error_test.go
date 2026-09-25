package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func TestIsAPIErrorNil(t *testing.T) {
	if IsAPIError(nil) {
		t.Fatal("IsAPIError(nil) = true, want false")
	}
}

func TestIsAPIErrorValue(t *testing.T) {
	err := types.HttpError{Code: "USER_NOT_FOUND", Message: "User not found", Status: 404}
	if !IsAPIError(err) {
		t.Fatal("IsAPIError(HttpError value) = false, want true")
	}
}

func TestIsAPIErrorPointer(t *testing.T) {
	err := &types.HttpError{Code: "USER_NOT_FOUND", Message: "User not found", Status: 404}
	if !IsAPIError(err) {
		t.Fatal("IsAPIError(*HttpError) = false, want true")
	}
}

func TestIsAPIErrorWrapped(t *testing.T) {
	inner := types.HttpError{Code: "INVALID_TOKEN", Message: "Invalid token", Status: 401}
	wrapped := fmt.Errorf("route failed: %w", inner)
	if !IsAPIError(wrapped) {
		t.Fatal("IsAPIError(wrapped HttpError) = false, want true")
	}
	wrappedPtr := fmt.Errorf("route failed: %w", &types.HttpError{Code: "X", Message: "x", Status: 500})
	if !IsAPIError(wrappedPtr) {
		t.Fatal("IsAPIError(wrapped *HttpError) = false, want true")
	}
}

func TestIsAPIErrorNegative(t *testing.T) {
	if IsAPIError(errors.New("boom")) {
		t.Fatal("IsAPIError(errors.New) = true, want false")
	}
	if IsAPIError(fmt.Errorf("plain failure")) {
		t.Fatal("IsAPIError(plain) = true, want false")
	}
}
