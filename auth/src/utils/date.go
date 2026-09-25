// Package utils date helper — GetDate parity (PARITY_V3.md gap 15).
//
// Upstream: vendor/better-auth/packages/better-auth/src/utils/date.ts @ 5468e6bf:
//
//	export const getDate = (span: number, unit: "sec" | "ms" = "ms") => {
//		return new Date(Date.now() + (unit === "sec" ? span * 1000 : span));
//	};
//
// Callers: cookies/index.ts getCookies/setCookieCache (getDate(maxAge, "sec")),
// api/routes/session.ts session refresh (getDate(expiresIn, "sec")). The
// cookies/ wiring itself is a later batch (cookies/ NOT owned here); this
// file only provides the helper.
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
