package utils

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaultSecretAgainstPinnedTypeScriptFixture(t *testing.T) {
	data, err := os.ReadFile("../../transpiler/fixtures/constants.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if got := expected["DEFAULT_SECRET"]; DefaultSecret != got {
		t.Fatalf("DefaultSecret = %q, expected %q", DefaultSecret, got)
	}
}
