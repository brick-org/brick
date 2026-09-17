package dsl

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse reads a single .resource.yaml file and returns the decoded ResourceFile.
func Parse(r io.Reader) (*ResourceFile, error) {
	var rf ResourceFile
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("dsl: parse: %w", err)
	}
	if err := validate(&rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

// ParseFile reads and parses a single .resource.yaml file from disk.
func ParseFile(path string) (*ResourceFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dsl: open %s: %w", path, err)
	}
	defer f.Close()
	rf, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rf, nil
}

// LoadDir scans dir for *.resource.yaml files, parses them, and returns
// all resources sorted by name (filename breaks ties), so codegen output
// is deterministic regardless of filesystem order.
func LoadDir(dir string) ([]*ResourceFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("dsl: read dir %s: %w", dir, err)
	}
	var resources []*ResourceFile
	filenames := map[*ResourceFile]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".resource.yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		rf, err := ParseFile(path)
		if err != nil {
			return nil, err
		}
		resources = append(resources, rf)
		filenames[rf] = e.Name()
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Name != resources[j].Name {
			return resources[i].Name < resources[j].Name
		}
		return filenames[resources[i]] < filenames[resources[j]]
	})
	return resources, nil
}
