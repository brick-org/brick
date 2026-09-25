package api

import (
	"fmt"
	"testing"
	"time"
)

func TestPruneRateLimitMemoryRemovesExpiredAndEnforcesCap(t *testing.T) {
	rateLimitMu.Lock()
	original := rateLimitMemory
	rateLimitMemory = make(map[string]memoryRateLimitEntry, memoryStoreMaxEntries+2)
	rateLimitMu.Unlock()
	t.Cleanup(func() {
		rateLimitMu.Lock()
		rateLimitMemory = original
		rateLimitMu.Unlock()
	})

	now := time.Now()
	rateLimitMemory["expired"] = memoryRateLimitEntry{ExpiresAt: now.Add(-time.Second)}
	for i := 0; i <= memoryStoreMaxEntries; i++ {
		rateLimitMemory[fmt.Sprintf("live-%d", i)] = memoryRateLimitEntry{ExpiresAt: now.Add(time.Hour)}
	}

	pruneRateLimitMemory(now)
	if _, exists := rateLimitMemory["expired"]; exists {
		t.Fatal("expired entry was not pruned")
	}
	if len(rateLimitMemory) >= memoryStoreMaxEntries {
		t.Fatalf("memory store size = %d, want less than %d before insertion", len(rateLimitMemory), memoryStoreMaxEntries)
	}
}
