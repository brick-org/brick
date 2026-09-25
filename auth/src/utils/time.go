// Package utils time-string parser — TimeString ms()/sec() parity (PARITY_V3.md gap 15).
//
// Upstream: vendor/better-auth/packages/better-auth/src/utils/time.ts @ 5468e6bf.
// Constants (ms): SEC 1000, MIN 60000, HOUR 3600000, DAY 86400000,
// WEEK 604800000, MONTH 2592000000 (30d), YEAR 31557600000 (365.25d).
// Grammar: [+|-][space]number[space]unit[space suffix], where unit is
// y/yr/yrs/year(s), mo/month(s), w/week(s), d/day(s), h/hr/hrs/hour(s),
// m/min/mins/minute(s), s/sec/secs/second(s) (any case, single optional
// spaces), suffix is "ago" (negates) or "from now" (positive). A prefix and
// a suffix together are invalid. Ms returns milliseconds, Sec returns
// Math.round(ms/1000).
//
// Excluded / by-design (do NOT implement here):
//   - keccak toChecksumAddress (utils/hashing.ts, ERC-55 via @noble/hashes):
//     no v1 email/password+session caller; excluded.
//   - safeCloneRequest (utils/request.ts, Request.clone with bodyless
//     fallback): Go has no Request.clone; the faithful equivalent is the
//     best-effort rebuild in api/requestFromContext and
//     api/routes callbackRequest/mergeVerifyPostStoredRequest (method+URL+
//     headers only, body referenced not cloned). By design, no counterpart
//     in this package.
package utils

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const (
	timeSEC   = 1000
	timeMIN   = timeSEC * 60
	timeHOUR  = timeMIN * 60
	timeDAY   = timeHOUR * 24
	timeWEEK  = timeDAY * 7
	timeMONTH = timeDAY * 30
	timeYEAR  = int64(float64(timeDAY) * 365.25)
)

var timeStringRe = regexp.MustCompile(`^(?i)(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?: (ago|from now))?$`)

// parseTimeString parses a TimeString into signed milliseconds.
func parseTimeString(value string) (float64, error) {
	match := timeStringRe.FindStringSubmatch(value)
	if match == nil || (match[4] != "" && match[1] != "") {
		return 0, fmt.Errorf("utils: invalid time string format: %q. Use formats like \"7d\", \"30m\", \"1 hour\", etc.", value)
	}
	n, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return 0, fmt.Errorf("utils: invalid time string format: %q. Use formats like \"7d\", \"30m\", \"1 hour\", etc.", value)
	}
	unit := strings.ToLower(match[3])
	var result float64
	switch unit {
	case "years", "year", "yrs", "yr", "y":
		result = n * float64(timeYEAR)
	case "months", "month", "mo":
		result = n * float64(timeMONTH)
	case "weeks", "week", "w":
		result = n * float64(timeWEEK)
	case "days", "day", "d":
		result = n * float64(timeDAY)
	case "hours", "hour", "hrs", "hr", "h":
		result = n * float64(timeHOUR)
	case "minutes", "minute", "mins", "min", "m":
		result = n * float64(timeMIN)
	case "seconds", "second", "secs", "sec", "s":
		result = n * float64(timeSEC)
	default:
		return 0, fmt.Errorf("utils: unknown time unit: %q", match[3])
	}
	if match[1] == "-" || strings.EqualFold(match[4], "ago") {
		return -result, nil
	}
	return result, nil
}

// Ms parses a TimeString and returns milliseconds, mirroring upstream ms().
//
// Fractional results are truncated toward zero when converting to int64
// (upstream returns a float; integer inputs — the v1 cookie/session use —
// are exact).
func Ms(value string) (int64, error) {
	ms, err := parseTimeString(value)
	if err != nil {
		return 0, err
	}
	return int64(ms), nil
}

// Sec parses a TimeString and returns seconds rounded to the nearest
// integer, mirroring upstream sec() (Math.round(ms/1000)).
func Sec(value string) (int64, error) {
	ms, err := parseTimeString(value)
	if err != nil {
		return 0, err
	}
	return int64(math.Round(ms / 1000)), nil
}
