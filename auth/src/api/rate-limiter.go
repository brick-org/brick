package api

import (
	"context"
	"fmt"
	"os"
	stdpath "path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type resolvedRateLimit struct {
	Key    string
	Window time.Duration
	Max    int
}

type memoryRateLimitEntry struct {
	Count       int
	LastRequest time.Time
	ExpiresAt   time.Time
}

// Match Better Auth's hard ceiling so spoofed/distinct keys cannot grow the
// process-wide fallback store without bound.
const memoryStoreMaxEntries = 100_000

var (
	rateLimitMu     sync.Mutex
	rateLimitMemory = map[string]memoryRateLimitEntry{}
)

// RateLimitStorage abstracts rate-limit state behind the single atomic
// consume primitive used upstream (`BetterAuthRateLimitStorage.consume`).
// The in-memory backend below is the default when no storage selector is
// configured; select the backend via Options.RateLimit (Storage,
// SecondaryStorage, CustomStorage) and see ValidateRateLimitStorage in
// index.go. The memory bound (memoryStoreMaxEntries) is enforced by the
// default backend regardless.
type RateLimitStorage interface {
	// Consume records one request for key and reports whether the request
	// exceeds max requests in window. retryAfter is the seconds to wait when
	// limited, 0 otherwise.
	Consume(key string, window time.Duration, max int) (retryAfter int, limited bool)
}

// MemoryRateLimitStorage is the default RateLimitStorage backend. It shares
// the process-wide rateLimitMemory map, so it stays consistent with the
// package-level isRateLimited/recordRateLimit helpers used by the middleware.
type MemoryRateLimitStorage struct{}

// Consume performs the check-and-increment atomically under a single lock so
// concurrent requests cannot all pass a stale read before any increment
// lands. It mirrors upstream's memory-backend consume: a missing or expired
// entry opens a fresh window, an entry at max is limited, otherwise the
// count increments and the window slides forward from now.
func (MemoryRateLimitStorage) Consume(key string, window time.Duration, max int) (int, bool) {
	now := time.Now()

	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	pruneRateLimitMemory(now)

	entry, ok := rateLimitMemory[key]
	if !ok || !now.Before(entry.ExpiresAt) {
		if !ok {
			rateLimitMemory[key] = memoryRateLimitEntry{
				Count:       1,
				LastRequest: now,
				ExpiresAt:   now.Add(window),
			}
			return 0, false
		}
		delete(rateLimitMemory, key)
		rateLimitMemory[key] = memoryRateLimitEntry{
			Count:       1,
			LastRequest: now,
			ExpiresAt:   now.Add(window),
		}
		return 0, false
	}
	if entry.Count >= max {
		return retryAfterSeconds(entry.LastRequest, window, now), true
	}
	entry.Count++
	entry.LastRequest = now
	entry.ExpiresAt = now.Add(window)
	rateLimitMemory[key] = entry
	return 0, false
}

// DatabaseRateLimitStorage is the atomic database rate-limit backend,
// mirroring upstream's createDatabaseStorageWrapper
// (vendor/.../src/api/rate-limiter/index.ts:115-245). Rows live in the
// rate-limit table (Model, default "rateLimit") as {key, count,
// lastRequest} with lastRequest in milliseconds since the epoch, matching
// the RateLimitSchema column contract.
//
// Consume semantics, mirroring upstream exactly:
//
//   - Fresh key: the window opens with Create only. An update here would
//     reset the count for a key a concurrent opener already created, letting
//     every racer pass; creating instead means one opener wins and the rest
//     fall through to re-read and be counted. A lost create race re-reads:
//     when the row now exists the call re-decides, otherwise the original
//     error fails closed (limited) since this interface cannot surface it.
//   - Window elapsed: reset guarded on the window (lastRequest lte the read
//     value) so a concurrent increment in a new window cannot be clobbered;
//     a missed guard re-reads and re-decides.
//   - Within the window: increment guarded on both the window and the max,
//     so a burst of concurrent requests can never exceed the limit; a missed
//     guard re-reads and re-decides (limited with a fresh retryAfter, or a
//     reset when the window rolled between the read and the write).
//
// The retry loop is bounded (databaseRateLimitMaxRetries); exhaustion fails
// closed. Expired rows are pruned best-effort with a cutoff derived from
// LongestWindowSeconds (default: the current rule window); pass the value
// from longestConfiguredRateLimitWindow so long-window rows survive short
// consumes, mirroring upstream's longestObservedWindow. When Background is
// set the prune runs through it (mirroring runInBackgroundOrAwait with a
// handler); otherwise it runs synchronously so the request awaits cleanup
// and survives teardown (mirroring runInBackgroundOrAwait without one).
// Prune errors go to OnPruneError and never fail the request.
//
// A nil DB fails closed (limited) instead of failing open.
type DatabaseRateLimitStorage struct {
	DB types.Adapter
	// Model overrides the rate-limit table name
	// (Options.RateLimit.ModelName). Empty means "rateLimit".
	Model string
	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time
	// LongestWindowSeconds bounds prune cutoff growth across rules.
	// Zero means the current rule window.
	LongestWindowSeconds int
	// Background dispatches prune work (Options.Advanced.BackgroundTasks.Handler).
	// Nil runs the prune synchronously in the request path.
	Background func(task func())
	// OnPruneError reports prune failures. Nil drops them.
	OnPruneError func(error)
}

// databaseRateLimitMaxRetries bounds the read-decide-write retry loop.
// Upstream recurses until the decision settles; every iteration observes a
// fresher row, so settling takes at most a couple of steps and exhaustion
// only happens under pathological contention.
const databaseRateLimitMaxRetries = 8

func (s DatabaseRateLimitStorage) modelName() string {
	if s.Model != "" {
		return s.Model
	}
	return "rateLimit"
}

func (s DatabaseRateLimitStorage) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Consume implements RateLimitStorage against the DB adapter. Storage errors
// fail closed (limited with the window as retryAfter) because this interface
// cannot surface them; the api middleware calls consumeDatabaseRateLimit
// directly so operational failures surface as 500s instead.
func (s DatabaseRateLimitStorage) Consume(key string, window time.Duration, max int) (int, bool) {
	windowSec := int(window / time.Second)
	if windowSec <= 0 {
		windowSec = 10
	}
	if max <= 0 {
		max = 100
	}
	if s.DB == nil {
		return windowSec, true
	}
	allowed, retryAfter, err := consumeDatabaseRateLimit(
		context.Background(), s.DB, s.modelName(), key,
		windowSec, max, s.LongestWindowSeconds, s.now(), s.Background, s.OnPruneError,
	)
	if err != nil {
		return windowSec, true
	}
	if !allowed {
		return retryAfter, true
	}
	return 0, false
}

// databaseLongestObserved persists the longest window seen per rate-limit
// model, mirroring upstream's longestObservedWindow closure
// (vendor/.../src/api/rate-limiter/index.ts:125,133-135): consume grows it
// when rule.window exceeds it, so later short-window consumes still prune
// with the long cutoff and active long-window rows survive. Static config
// (longestConfiguredRateLimitWindow, which excludes function resolvers like
// upstream) seeds it; dynamic resolver windows grow it per consume.
var (
	databaseLongestMu       sync.Mutex
	databaseLongestObserved = map[string]int{}
)

// resetDatabaseLongestObserved clears the longest-observed registry (tests
// only). Production code never calls it.
func resetDatabaseLongestObserved() {
	databaseLongestMu.Lock()
	defer databaseLongestMu.Unlock()
	databaseLongestObserved = map[string]int{}
}

// observeDatabaseWindow returns the effective prune window for model: the max
// of the static seed, the current rule window, and any previously observed
// window, persisting the max for future consumes.
func observeDatabaseWindow(model string, windowSec, staticLongest int) int {
	longest := staticLongest
	if windowSec > longest {
		longest = windowSec
	}
	databaseLongestMu.Lock()
	defer databaseLongestMu.Unlock()
	if seen, ok := databaseLongestObserved[model]; ok && seen > longest {
		longest = seen
	}
	if cur, ok := databaseLongestObserved[model]; !ok || longest > cur {
		databaseLongestObserved[model] = longest
	}
	return longest
}

// ConsumeResolvedRateLimit enforces one resolved bucket (global or plugin) in
// a single atomic step through the selected backend, mirroring upstream
// onRequestRateLimit's single-step consume
// (vendor/.../src/api/rate-limiter/index.ts:418-437): the whole
// check-and-increment happens here in the request phase; there is no separate
// response-phase write-back, so concurrent requests cannot all pass a stale
// read before any increment lands.
//
// Backend routing mirrors getRateLimitStorage: custom storage first, then the
// configured Storage (secondary-storage via SecondaryStorage.Increment,
// database via consumeDatabaseRateLimit, memory via the selected
// RateLimitStorage). Storage failures return an error so callers fail the
// request with a 500 (mirroring upstream, where a storage throw fails the
// request) instead of silently limiting or passing. Plugin buckets use the
// same backend as global buckets; the memory-only two-phase
// isRateLimited/recordRateLimit pair must not be used for enforcement.
//
// Upstream TypeScript name: onRequestRateLimit (consume part).
func ConsumeResolvedRateLimit(ctx context.Context, config resolvedRateLimit, opts types.Options) (allowed bool, retryAfter int, err error) {
	windowSec := int(config.Window / time.Second)
	if windowSec <= 0 {
		windowSec = 10
	}
	max := config.Max
	if max <= 0 {
		max = 100
	}
	if opts.RateLimit.CustomStorage != nil {
		result, cerr := opts.RateLimit.CustomStorage.Consume(config.Key, types.RateLimitRule{Window: windowSec, Max: max})
		if cerr != nil {
			return false, windowSec, cerr
		}
		if !result.Allowed {
			if result.RetryAfter != nil {
				return false, *result.RetryAfter, nil
			}
			return false, windowSec, nil
		}
		return true, 0, nil
	}
	switch selectRateLimitBackend(opts) {
	case rateLimitBackendSecondary:
		if opts.SecondaryStorage == nil {
			return false, windowSec, fmt.Errorf("auth: secondary-storage rate limiting requires SecondaryStorage")
		}
		count, cerr := opts.SecondaryStorage.Increment(config.Key, windowSec)
		if cerr != nil {
			return false, windowSec, cerr
		}
		if count > int64(max) {
			return false, windowSec, nil
		}
		return true, 0, nil
	case rateLimitBackendDatabase:
		if opts.DB == nil {
			return false, windowSec, fmt.Errorf("auth: database rate limiting requires options.DB")
		}
		model := opts.RateLimit.ModelName
		if model == "" {
			model = "rateLimit"
		}
		staticLongest := longestConfiguredRateLimitWindow(opts)
		return consumeDatabaseRateLimit(ctx, opts.DB, model, config.Key, windowSec, max, staticLongest, time.Now(), databaseRateLimitBackground(opts), databaseRateLimitPruneLogger(opts))
	default:
		retryAfter, limited := rateLimitStorage.Consume(config.Key, config.Window, config.Max)
		return !limited, retryAfter, nil
	}
}

// consumeDatabaseRateLimit is the error-returning core behind
// DatabaseRateLimitStorage.Consume, mirroring upstream's database consume
// (vendor/.../src/api/rate-limiter/index.ts:133-224). now is the observation
// instant for the whole step; longestWindowSec seeds the prune cutoff (values
// below windowSec are raised to it).
func consumeDatabaseRateLimit(ctx context.Context, db types.Adapter, model, key string, windowSec, max, longestWindowSec int, now time.Time, background func(func()), onPruneError func(error)) (allowed bool, retryAfter int, err error) {
	longestWindowSec = observeDatabaseWindow(model, windowSec, longestWindowSec)
	windowMs := int64(windowSec) * 1000
	nowMs := now.UnixMilli()
	longestMs := int64(longestWindowSec) * 1000
	if longestMs < windowMs {
		longestMs = windowMs
	}
	prune := func() {
		cutoff := nowMs - longestMs
		if _, derr := db.DeleteMany(ctx, model, []types.Where{
			{Field: "lastRequest", Operator: types.OpLt, Value: cutoff},
		}); derr != nil && onPruneError != nil {
			onPruneError(derr)
		}
	}
	dispatchPrune := func() {
		if background != nil {
			background(prune)
			return
		}
		prune()
	}
	readRow := func() (count int64, lastRequestMs int64, found bool, rerr error) {
		row, rerr := db.FindOne(ctx, model, []types.Where{{Field: "key", Value: key}}, nil)
		if rerr != nil || row == nil {
			return 0, 0, row != nil, rerr
		}
		count, _ = rateLimitCountValue(row["count"])
		lastRequestMs, _ = rateLimitLastRequestMs(row["lastRequest"])
		return count, lastRequestMs, true, nil
	}
	for i := 0; i < databaseRateLimitMaxRetries; i++ {
		count, lastMs, found, rerr := readRow()
		if rerr != nil {
			return false, windowSec, rerr
		}
		_ = count
		if !found {
			if _, cerr := db.Create(ctx, model, map[string]any{
				"key": key, "count": 1, "lastRequest": nowMs,
			}, nil); cerr != nil {
				_, _, refound, rerr := readRow()
				if rerr != nil {
					return false, windowSec, rerr
				}
				if !refound {
					return false, windowSec, cerr
				}
				continue
			}
			dispatchPrune()
			return true, 0, nil
		}
		if nowMs-lastMs >= windowMs {
			updated, uerr := db.IncrementOne(ctx, model,
				[]types.Where{
					{Field: "key", Value: key},
					{Field: "lastRequest", Operator: types.OpLte, Value: lastMs},
				},
				nil,
				map[string]any{"count": 1, "lastRequest": nowMs})
			if uerr != nil {
				return false, windowSec, uerr
			}
			if updated != nil {
				dispatchPrune()
				return true, 0, nil
			}
			continue
		}
		windowStart := nowMs - windowMs
		updated, uerr := db.IncrementOne(ctx, model,
			[]types.Where{
				{Field: "key", Value: key},
				{Field: "lastRequest", Operator: types.OpGt, Value: windowStart},
				{Field: "count", Operator: types.OpLt, Value: int64(max)},
			},
			map[string]int{"count": 1},
			map[string]any{"lastRequest": nowMs})
		if uerr != nil {
			return false, windowSec, uerr
		}
		if updated != nil {
			return true, 0, nil
		}
		freshCount, freshLast, refound, rerr := readRow()
		if rerr != nil {
			return false, windowSec, rerr
		}
		_ = freshCount
		if !refound {
			continue
		}
		if nowMs-freshLast >= windowMs {
			continue
		}
		return false, databaseRetryAfterMs(freshLast, windowMs, nowMs), nil
	}
	return false, windowSec, nil
}

// databaseRetryAfterMs mirrors upstream getRetryAfter
// (vendor/.../src/api/rate-limiter/index.ts:109-113): ceiling seconds from
// now until the window slides, minimum 1.
func databaseRetryAfterMs(lastRequestMs, windowMs, nowMs int64) int {
	retryAfter := int((lastRequestMs + windowMs - nowMs + 999) / 1000)
	if retryAfter < 1 {
		retryAfter = 1
	}
	return retryAfter
}

// rateLimitCountValue normalizes a rate-limit count cell across adapter
// numeric decodings.
func rateLimitCountValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > 1<<63-1 {
			return 0, false
		}
		return int64(n), true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

// rateLimitLastRequestMs normalizes a lastRequest cell to ms since the
// epoch, accepting the numeric ms form upstream stores plus time.Time and
// numeric strings for adapter decode variance.
func rateLimitLastRequestMs(v any) (int64, bool) {
	if ms, ok := rateLimitCountValue(v); ok {
		return ms, true
	}
	if t, ok := v.(time.Time); ok {
		return t.UnixMilli(), true
	}
	if s, ok := v.(string); ok {
		if ms, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return ms, true
		}
	}
	return 0, false
}

// longestConfiguredRateLimitWindow returns the longest rate-limit window in
// seconds across the global default, the default special rules, plugin rules,
// and static custom rules, mirroring upstream getConfiguredRateLimitWindows
// (vendor/.../src/api/rate-limiter/index.ts:247-268). Function-valued custom
// rules (CustomRuleResolvers) are excluded like upstream excludes function
// entries: their windows are unknowable without a request. The result seeds
// database prune cutoffs so long-window rows survive short consumes.
func longestConfiguredRateLimitWindow(opts types.Options) int {
	longest := opts.RateLimit.WindowOrDefault()
	for _, rule := range defaultSpecialRateLimitRules {
		if rule.window > longest {
			longest = rule.window
		}
	}
	for _, plugin := range opts.Plugins {
		provider, ok := plugin.(types.PluginRateLimitProvider)
		if !ok {
			continue
		}
		for _, rule := range provider.RateLimitRules() {
			window := rule.Window
			if window <= 0 {
				window = 10
			}
			if window > longest {
				longest = window
			}
		}
	}
	for _, rule := range opts.RateLimit.CustomRules {
		if rule.Window > longest {
			longest = rule.Window
		}
	}
	if longest <= 0 {
		longest = 10
	}
	return longest
}

// rateLimitStorage is the backend consulted by the middleware. It defaults
// to the in-memory implementation; tests and integrators may swap it via
// SetRateLimitStorage.
var rateLimitStorage RateLimitStorage = MemoryRateLimitStorage{}

// SetRateLimitStorage swaps the rate-limit backend (e.g. to a database or
// secondary-storage implementation of RateLimitStorage). It returns a restore
// function. The default is the in-memory backend; rate limiting itself stays
// disabled unless RateLimit.Enabled is explicitly set.
func SetRateLimitStorage(storage RateLimitStorage) (restore func()) {
	previous := rateLimitStorage
	if storage != nil {
		rateLimitStorage = storage
	}
	return func() { rateLimitStorage = previous }
}

func useRateLimitMiddleware(api huma.API, basePath string, opts types.Options) {
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		config, ok := resolveRateLimit(ctx, basePath, opts)
		if !ok {
			next(ctx)
			return
		}

		if retryAfter, limited := isRateLimited(config); limited {
			writeRateLimitResponse(ctx, retryAfter)
			return
		}

		next(ctx)
		recordRateLimit(config)
	})
}

// rateLimitEnabled reports whether rate limiting applies, mirroring upstream
// `enabled ?? isProduction`
// (vendor/.../src/context/create-context.ts:356): an explicit Enabled wins;
// otherwise limiting is on only when NODE_ENV is "production". This lives
// here (not in types.EnabledValue, which is frozen read-only) so the
// production default is honored without changing the types surface.
func rateLimitEnabled(opts types.Options) bool {
	if opts.RateLimit.Enabled != nil {
		return *opts.RateLimit.Enabled
	}
	return os.Getenv("NODE_ENV") == "production"
}

// noTrustedIPKey is the sentinel IP segment for the shared rate-limit bucket
// used when no trusted client IP can be derived. It is not a valid IP, so it
// never collides with a real client IP key. Mirrors upstream NO_TRUSTED_IP_KEY
// (vendor/.../src/api/rate-limiter/index.ts:335).
const noTrustedIPKey = "no-trusted-ip"

var (
	rateLimitIPWarnMu sync.Mutex
	rateLimitIPWarned bool
)

// resetRateLimitIPWarning clears the missing-IP warning latch (tests only).
func resetRateLimitIPWarning() {
	rateLimitIPWarnMu.Lock()
	rateLimitIPWarned = false
	rateLimitIPWarnMu.Unlock()
}

// logRateLimitNoIPWarning warns once that rate limiting fell back to the
// shared per-path bucket, mirroring upstream's ipWarningLogged branch
// (vendor/.../src/api/rate-limiter/index.ts:347-355).
func logRateLimitNoIPWarning(opts types.Options) {
	rateLimitIPWarnMu.Lock()
	warned := rateLimitIPWarned
	rateLimitIPWarned = true
	rateLimitIPWarnMu.Unlock()
	if warned {
		return
	}
	apiLogf(opts, "warn", "auth: rate limiting could not determine a client IP and is falling back to a single shared per-path bucket. Ensure your runtime forwards a trusted client IP header, then set `advanced.ipAddress.ipAddressHeaders` or `advanced.ipAddress.trustedProxies` so the address can be resolved.")
}

// rateLimitClientIP resolves the bucket IP segment for rate limiting. An
// empty resolution fails closed to the shared noTrustedIPKey bucket (mirroring
// upstream) instead of skipping limiting (which let a client omit the IP
// header to bypass the limit); only explicit DisableIPTracking skips, with ok
// false. proxyAware selects RequestClientIP (trusted-proxy/CIDR/IPv6-subnet
// resolution) over the legacy requestIP single-value trust.
func rateLimitClientIP(ctx huma.Context, opts types.Options, proxyAware bool) (string, bool) {
	var ip string
	if proxyAware {
		ip = RequestClientIP(ctx, opts)
	} else {
		ip = requestIP(ctx, opts)
	}
	if ip != "" {
		return ip, true
	}
	if opts.Advanced.IPAddress.DisableIPTracking {
		return "", false
	}
	logRateLimitNoIPWarning(opts)
	return noTrustedIPKey, true
}

func resolveRateLimit(ctx huma.Context, basePath string, opts types.Options) (resolvedRateLimit, bool) {
	if !rateLimitEnabled(opts) {
		return resolvedRateLimit{}, false
	}

	clientIP, ok := rateLimitClientIP(ctx, opts, false)
	if !ok {
		return resolvedRateLimit{}, false
	}

	path := normalizeRateLimitPath(ctx.URL().Path, basePath)
	window, max, ok := applyRateLimitRules(ctx, path, opts)
	if !ok {
		return resolvedRateLimit{}, false
	}

	return resolvedRateLimit{
		Key:    clientIP + "|" + path,
		Window: window,
		Max:    max,
	}, true
}

func resolvePluginRateLimit(ctx huma.Context, basePath string, opts types.Options) (resolvedRateLimit, bool) {
	// Plugin rules are part of the upstream rate-limit config, so they honor
	// the same production-default enabled gate (upstream returns early when
	// rate limiting is disabled).
	if !rateLimitEnabled(opts) {
		return resolvedRateLimit{}, false
	}
	// Proxy-aware resolution (trusted-proxy chains, IPv6 subnets), matching
	// the global middleware: spoofed chain entries must not escape the bucket.
	clientIP, ok := rateLimitClientIP(ctx, opts, true)
	if !ok {
		return resolvedRateLimit{}, false
	}

	path := middlewareRateLimitPath(ctx.URL().Path, basePath, opts)
	for _, plugin := range opts.Plugins {
		provider, ok := plugin.(types.PluginRateLimitProvider)
		if !ok {
			continue
		}
		for _, rule := range provider.RateLimitRules() {
			if rule.PathMatcher == nil || !rule.PathMatcher(path) {
				continue
			}
			window := rule.Window
			if window <= 0 {
				window = 10
			}
			max := rule.Max
			if max <= 0 {
				max = 100
			}
			return resolvedRateLimit{
				Key:    clientIP + "|plugin|" + plugin.ID() + "|" + path,
				Window: time.Duration(window) * time.Second,
				Max:    max,
			}, true
		}
	}
	return resolvedRateLimit{}, false
}

func normalizeRateLimitPath(requestPath, basePath string) string {
	trimmedBasePath := strings.TrimSuffix(basePath, "/")
	path := strings.TrimPrefix(requestPath, trimmedBasePath)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// applyRateLimitRules folds the global default, the default special rules,
// static custom rules, and function-valued custom resolvers into one
// window/max pair for path, mirroring upstream resolveRateLimitConfig
// (vendor/.../src/api/rate-limiter/index.ts:337-410): special rules first,
// then plugin rules (enforced separately here — see resolvePluginRateLimit),
// then custom rules where a function entry receives the request plus the
// current rule and may replace it or return false to disable limiting for
// the request. ok false means limiting is disabled for this request.
func applyRateLimitRules(ctx huma.Context, path string, opts types.Options) (window time.Duration, max int, ok bool) {
	window = time.Duration(opts.RateLimit.WindowOrDefault()) * time.Second
	max = opts.RateLimit.MaxOrDefault()

	if specialRule, ok := defaultRateLimitRule(path); ok {
		window = time.Duration(specialRule.Window) * time.Second
		max = specialRule.Max
	}

	if customRule, ok := customRateLimitRule(path, opts.RateLimit.CustomRules); ok {
		if customRule.Disabled {
			return 0, 0, false
		}
		if customRule.Window > 0 {
			window = time.Duration(customRule.Window) * time.Second
		}
		if customRule.Max > 0 {
			max = customRule.Max
		}
	}

	if resolver, ok := customRuleResolver(path, opts.RateLimit.CustomRuleResolvers); ok && resolver != nil {
		current := types.RateLimitRule{Window: int(window / time.Second), Max: max}
		resolved, apply := resolver(requestFromContext(ctx), current)
		if !apply {
			return 0, 0, false
		}
		// Wholesale replace like upstream, keeping the current value for
		// non-positive fields (Go zero values mean "no override" where
		// upstream always carries concrete numbers).
		if resolved.Window > 0 {
			window = time.Duration(resolved.Window) * time.Second
		}
		if resolved.Max > 0 {
			max = resolved.Max
		}
	}

	return window, max, true
}

// specialRateLimitRule is one entry of the upstream default special-rule
// table (vendor/.../src/api/rate-limiter/index.ts:439-467).
type specialRateLimitRule struct {
	match       func(path string) bool
	window, max int
}

// defaultSpecialRateLimitRules mirrors upstream getDefaultSpecialRules: tight
// auth-mutation limits plus the slower email/OTP abuse paths.
var defaultSpecialRateLimitRules = []specialRateLimitRule{
	{
		match: func(path string) bool {
			return strings.HasPrefix(path, "/sign-in") ||
				strings.HasPrefix(path, "/sign-up") ||
				strings.HasPrefix(path, "/change-password") ||
				strings.HasPrefix(path, "/change-email")
		},
		window: 10,
		max:    3,
	},
	{
		match: func(path string) bool {
			return path == "/request-password-reset" ||
				path == "/send-verification-email" ||
				strings.HasPrefix(path, "/forget-password") ||
				path == "/email-otp/send-verification-otp" ||
				path == "/email-otp/request-password-reset"
		},
		window: 60,
		max:    3,
	},
}

func defaultRateLimitRule(path string) (types.RateLimitRule, bool) {
	for _, rule := range defaultSpecialRateLimitRules {
		if rule.match(path) {
			return types.RateLimitRule{Window: rule.window, Max: rule.max}, true
		}
	}
	return types.RateLimitRule{}, false
}

// customRuleResolver finds the function-valued custom rule for path,
// mirroring the wildcard/exact lookup upstream applies to customRules
// (vendor/.../src/api/rate-limiter/index.ts:382-389). Exact keys win;
// wildcard keys apply in sorted order for determinism.
func customRuleResolver(path string, resolvers map[string]types.RateLimitRuleResolver) (types.RateLimitRuleResolver, bool) {
	if len(resolvers) == 0 {
		return nil, false
	}
	if resolver, ok := resolvers[path]; ok && resolver != nil {
		return resolver, true
	}
	keys := make([]string, 0, len(resolvers))
	for key, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		if strings.Contains(key, "*") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		matched, err := stdpath.Match(key, path)
		if err == nil && matched {
			return resolvers[key], true
		}
	}
	return nil, false
}

func customRateLimitRule(path string, rules map[string]types.RateLimitRule) (types.RateLimitRule, bool) {
	if len(rules) == 0 {
		return types.RateLimitRule{}, false
	}

	if rule, ok := rules[path]; ok {
		return rule, true
	}

	keys := make([]string, 0, len(rules))
	for key := range rules {
		if strings.Contains(key, "*") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	// Match wildcard rules deterministically.
	for _, key := range keys {
		matched, err := stdpath.Match(key, path)
		if err == nil && matched {
			return rules[key], true
		}
	}

	return types.RateLimitRule{}, false
}

// defaultIPHeaders mirrors the header set consulted when no explicit
// Advanced.IPAddress.IPAddressHeaders list is configured. X-Forwarded-For is
// checked first (upstream default); X-Real-IP is a Go-compat fallback for
// single-proxy deployments that only set it.
var defaultIPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}

// requestIP resolves the client IP for rate limiting with trusted-proxy
// awareness mirroring upstream getIP/getIPFromHeader:
//
//   - When Advanced.IPAddress.DisableIPTracking is set, it returns "" and the
//     caller skips limiting (mirrors upstream returning null).
//   - Headers are walked in Advanced.IPAddress.IPAddressHeaders order
//     (default X-Forwarded-For, then X-Real-IP).
//   - Without proxy trust, only a single-value forwarded header is trusted: a
//     multi-hop X-Forwarded-For chain is unresolvable (its leftmost token is
//     client-spoofable), so the header is skipped and resolution falls through
//     to the next header and finally RemoteAddr.
//   - The types-level options expose no trusted-proxy CIDR list, so proxy
//     trust is opt-in via Advanced.TrustedProxyHeaders=true; when set, the
//     leftmost X-Forwarded-For hop is accepted as the client (single-hop
//     trust for deployments where the edge proxy is known to append).
//
// Rate limiting stays disabled unless RateLimit.Enabled is explicitly set;
// none of the above enables it.
func requestIP(ctx huma.Context, opts types.Options) string {
	if opts.Advanced.IPAddress.DisableIPTracking {
		return ""
	}
	headers := opts.Advanced.IPAddress.IPAddressHeaders
	if len(headers) == 0 {
		headers = defaultIPHeaders
	}
	trustProxyChain := opts.Advanced.TrustedProxyHeaders != nil && *opts.Advanced.TrustedProxyHeaders
	for _, header := range headers {
		value := strings.TrimSpace(ctx.Header(header))
		if value == "" {
			continue
		}
		if strings.EqualFold(header, "X-Forwarded-For") && strings.Contains(value, ",") {
			if !trustProxyChain {
				// Multi-hop chain with no trusted-proxy opt-in: unresolvable.
				continue
			}
			value = strings.TrimSpace(strings.Split(value, ",")[0])
		} else if strings.EqualFold(header, "X-Forwarded-For") {
			value = strings.TrimSpace(strings.Split(value, ",")[0])
		}
		if ip := stripPort(value); ip != "" {
			return ip
		}
	}

	return stripPort(strings.TrimSpace(ctx.RemoteAddr()))
}

func retryAfterSeconds(lastRequest time.Time, window time.Duration, now time.Time) int {
	retryAfter := int(lastRequest.Add(window).Sub(now).Seconds())
	if lastRequest.Add(window).After(now) && lastRequest.Add(window).Sub(now)%time.Second != 0 {
		retryAfter++
	}
	if retryAfter < 1 {
		retryAfter = 1
	}
	return retryAfter
}

func isRateLimited(config resolvedRateLimit) (int, bool) {
	now := time.Now()

	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	pruneRateLimitMemory(now)

	entry, ok := rateLimitMemory[config.Key]
	if !ok {
		return 0, false
	}
	if !now.Before(entry.ExpiresAt) {
		delete(rateLimitMemory, config.Key)
		return 0, false
	}
	if entry.Count < config.Max {
		return 0, false
	}

	return retryAfterSeconds(entry.LastRequest, config.Window, now), true
}

func recordRateLimit(config resolvedRateLimit) {
	now := time.Now()

	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	pruneRateLimitMemory(now)

	entry, ok := rateLimitMemory[config.Key]
	if !ok || !now.Before(entry.ExpiresAt) {
		rateLimitMemory[config.Key] = memoryRateLimitEntry{
			Count:       1,
			LastRequest: now,
			ExpiresAt:   now.Add(config.Window),
		}
		return
	}

	entry.Count++
	entry.LastRequest = now
	entry.ExpiresAt = now.Add(config.Window)
	rateLimitMemory[config.Key] = entry
}

func pruneRateLimitMemory(now time.Time) {
	for key, entry := range rateLimitMemory {
		if !now.Before(entry.ExpiresAt) {
			delete(rateLimitMemory, key)
		}
	}
	for len(rateLimitMemory) >= memoryStoreMaxEntries {
		// Go maps are unordered, so evict an arbitrary live entry. The security
		// property is the hard memory bound; exact LRU order is not observable.
		for key := range rateLimitMemory {
			delete(rateLimitMemory, key)
			break
		}
	}
}

// writeRateLimitResponse replies 429 with the upstream
// {"message":"Too many requests. Please try again later."} body (kept
// intentionally distinct from the huma {status,title,detail} error shape so
// clients can distinguish upstream-parity rate limiting from hook errors) and
// an X-Retry-After header with the seconds until the window slides.
func writeRateLimitResponse(ctx huma.Context, retryAfter int) {
	// Headers must precede the status: huma adapters (and net/http)
	// flush headers on WriteHeader, so setting them after SetStatus
	// silently drops X-Retry-After/content-type.
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetHeader("X-Retry-After", strconv.Itoa(retryAfter))
	ctx.SetStatus(429)
	_, _ = ctx.BodyWriter().Write([]byte(`{"message":"Too many requests. Please try again later."}`))
}
