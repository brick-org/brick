package auth_test

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// stubSecondaryStorage is a minimal auth.SecondaryStorage for constructor
type stubSecondaryStorage struct {
	values map[string]string
}

func newStubSecondaryStorage() *stubSecondaryStorage {
	return &stubSecondaryStorage{values: map[string]string{}}
}

func (s *stubSecondaryStorage) Get(key string) (any, error) { return s.values[key], nil }
func (s *stubSecondaryStorage) GetAndDelete(key string) (any, error) {
	v := s.values[key]
	delete(s.values, key)
	return v, nil
}
func (s *stubSecondaryStorage) Increment(key string, _ int) (int64, error) { return 1, nil }
func (s *stubSecondaryStorage) Set(key, value string, _ *int) error {
	s.values[key] = value
	return nil
}
func (s *stubSecondaryStorage) Delete(key string) error { delete(s.values, key); return nil }

func TestNew_AcceptsSecondaryStorageSessionFlagsWithBackend(t *testing.T) {
	api := newTestAPI(t)
	db := newMemoryAdapter()
	for name, session := range map[string]auth.SessionOptions{
		"storeSessionInDatabase":    {StoreSessionInDatabase: true},
		"preserveSessionInDatabase": {StoreSessionInDatabase: true, PreserveSessionInDatabase: true},
	} {
		if _, err := auth.BetterAuth(auth.Options{
			Secret:           "test-secret",
			Adapter:          api.Adapter(),
			DB:               db,
			SecondaryStorage: newStubSecondaryStorage(),
			Session:          session,
		}); err != nil {
			t.Fatalf("%s: BetterAuth with a secondary backend must succeed, got %v", name, err)
		}
	}
}

func TestNew_RejectsSecondaryStorageSessionFlagsWithoutBackend(t *testing.T) {
	api := newTestAPI(t)
	_, err := auth.BetterAuth(auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		DB:      newMemoryAdapter(),
		Session: auth.SessionOptions{StoreSessionInDatabase: true},
	})
	if err == nil {
		t.Fatal("session secondary-storage flags without a backend must fail")
	}
	if !strings.Contains(err.Error(), "SecondaryStorage") {
		t.Fatalf("error must name SecondaryStorage, got %q", err.Error())
	}
}

func TestNew_AcceptsSecondaryStorageWithoutSessionFlags(t *testing.T) {
	api := newTestAPI(t)
	if _, err := auth.BetterAuth(auth.Options{
		Secret:           "test-secret",
		Adapter:          api.Adapter(),
		DB:               newMemoryAdapter(),
		SecondaryStorage: newStubSecondaryStorage(),
	}); err != nil {
		t.Fatalf("secondary storage without session flags must succeed, got %v", err)
	}
}
