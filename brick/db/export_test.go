package db

// Test-only exports for unexported pure helpers. Production code must go
// through List/ListMap; these exist so clamp/sort/escape math is unit
// tested without a database.

// NormalizePageLimitForTest exposes normalizePageLimit.
func NormalizePageLimitForTest(page, limit int) (int, int) {
	return normalizePageLimit(page, limit)
}

// NormalizeSortForTest exposes normalizeSort.
func NormalizeSortForTest(sort string, sortable []string) (col, dir string, ok bool) {
	return normalizeSort(sort, sortable)
}

// EscapeLikeForTest exposes escapeLike.
func EscapeLikeForTest(s string) string { return escapeLike(s) }

// SearchGroupForTest exposes searchGroup.
func SearchGroupForTest(search string, searchable []string) *Where {
	return searchGroup(search, searchable)
}
