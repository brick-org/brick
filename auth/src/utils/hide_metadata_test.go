package utils

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestHideMetadataAgainstPinnedTypeScriptFixture(t *testing.T) {
	data, err := os.ReadFile("../../transpiler/fixtures/hide-metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(HideMetadata, expected) {
		t.Fatalf("HideMetadata = %#v, expected %#v", HideMetadata, expected)
	}
}
