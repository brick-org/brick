# auth/testdata — upstream golden fixtures (AUTH-R5-04)

Wire-compatibility vectors shared with the pinned TypeScript implementation.
Waves 1–4 proved behavior with inline constants; this directory checks the
vectors into the repository so every direction (Go-write/TS-read,
TS-write/Go-read) is exercised from stable files instead of hand-copied
strings.

Target: Better Auth **v1.7.5** at `vendor/better-auth` commit
`5468e6bfcdff799848537cf5ad06ebab15aad9dd`.

## Layout

| File | Wire format | Upstream source |
|---|---|---|
| `email_jwt.json` | Email HS256 JWT (`SignJWT` `{alg HS256}`, lowercased email, `iat`/`exp`) | `packages/better-auth/src/api/routes/email-verification.ts` (`createEmailVerificationToken`), `packages/better-auth/src/crypto/jwt.ts` |
| `xchacha.json` | XChaCha20-Poly1305 bare-hex payload + `$ba$<v>$<hex>` envelope | `packages/better-auth/src/crypto/index.ts` (`symmetricEncrypt`, `symmetricDecrypt`, `formatEnvelope`, `parseEnvelope`) |
| `session_jwt.json` | Session-data cache JWT (HS256 over auth secret, `session`/`user`/`updatedAt`/`version?`/`iat`/`exp`) | `packages/better-auth/src/cookies/index.ts` (`setCookieCache`/`decodeCookieCache`, jwt branch), `packages/better-auth/src/crypto/jwt.ts` (`signSecretJWT`/`verifySecretJWT`) |
| `session_jwe.json` | Session-data cache JWE (`dir`/`A256CBC-HS512`, HKDF-derived key, thumbprint `kid`, `iat`/`exp`/`jti`, 15s tolerance) | `packages/better-auth/src/cookies/index.ts` (jwe branch), `packages/better-auth/src/crypto/jwt.ts` (`symmetricEncodeJWT`/`symmetricDecodeJWT`, `deriveEncryptionSecret`) |
| `jwk.json`, `jwks.json` | EdDSA JWK pair (TEST-ONLY private half), signed JWT, JWKS set | `packages/better-auth/src/crypto/jwt.ts`, `packages/plugins/jwt` (rotation/grace) |
| `cookies.json` | `value.hmac` Sign/Verify vectors (incl. RFC 4231 case 2) + chunk naming | `packages/better-auth/src/cookies/index.ts` (`createAuthCookie`, chunk helpers), `packages/better-auth/src/crypto` HMAC signing |
| `provenance.json` | Machine-checkable provenance for every fixture above | — (this task) |

## Repeatable generation

```bash
# From auth/: regenerate all time-sensitive fixtures with the Go helpers
# (uses only the in-repo crypto/cookie helpers — no network).
./scripts/gen-fixtures.sh

# Opt-in: also dump reference vectors from the pinned TS tree with
# targeted vitest runs (never the full suite). Requires pnpm install
# in vendor/better-auth; hermetic CI never needs this.
./scripts/gen-fixtures.sh --ts
```

`gen-fixtures.sh` wraps the Go generator at `scripts/genfixtures/main.go`.
The `--ts` path runs only targeted commands of the form

```bash
pnpm --dir <vendor/better-auth> vitest run <path-to-test> -t '<pattern>'
```

e.g. `packages/better-auth/src/state.test.ts`,
`packages/better-auth/src/crypto` secret-rotation tests, and the
`kick` provider tests — each scoped with `-t` to a single pattern so the
full upstream suite is never executed. Captured TS output is compared
against the checked-in vectors; mismatches fail the script without
modifying fixtures until a human promotes the new values.

Provenance (upstream file, upstream test, pinned commit, exact generation
command) is recorded in `provenance.json` and summarized in the table
above. Every fixture consumer is `auth/testutil` (`fixtures_test.go`,
`providers_test.go`); see its package doc for the both-directions matrix.

## Expiry policy

Crypto fixtures that carry `exp` (email JWT, session JWT/JWE, JWK-signed
JWT) are minted with a ~10-year window so hermetic CI stays green without
re-generation. They remain **test vectors, not credentials**: every secret
and private key in this directory is a fixture-only value (`auth-r5-04-…`)
and must never be used outside tests. Re-run `gen-fixtures.sh` if a vector
approaches expiry or after any wire-format change.

## Live smoke (opt-in only)

No fixture test touches the network in normal CI (stub transports +
`httptest` servers only). `auth/testutil` exposes one opt-in live check
gated on `BRICK_AUTH_LIVE_SMOKE=1` that performs best-effort `HEAD`
requests against the documented provider authorize endpoints; it is
skipped by default and never gates CI.
