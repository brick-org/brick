// Package utils date helper.
// Upstream: date.ts getDate.
// Excluded / by-design (do NOT implement here):
package utils

import "time"

// GetDate returns now + span in the given unit, mirroring upstream getDate.
//
// span is a duration magnitude; unit "sec" interprets it as seconds,
// anything else (including "" for the upstream "ms" default) as
// milliseconds. Unknown units fall through to milliseconds, matching the
// upstream ternary (unit === "sec" ? span*1000 : span).
func GetDate(span int64, unit string) time.Time {
	now := time.Now()
	if unit == "sec" {
		return now.Add(time.Duration(span) * time.Second)
	}
	return now.Add(time.Duration(span) * time.Millisecond)
}
