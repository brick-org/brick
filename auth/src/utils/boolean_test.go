package utils

import (
	"encoding/json"
	"os"
	"testing"
)

func TestToBooleanAgainstPinnedTypeScriptFixtures(t *testing.T) {
	data, err := os.ReadFile("../../transpiler/fixtures/boolean.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Value    any  `json:"value"`
		Expected bool `json:"expected"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, entry := range cases {
		if got := ToBoolean(entry.Value); got != entry.Expected {
			t.Errorf("ToBoolean(%#v) = %v, expected %v", entry.Value, got, entry.Expected)
		}
	}
}
