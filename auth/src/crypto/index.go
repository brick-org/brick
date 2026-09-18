// Package crypto implements the Better Auth cryptography surface.
//
// Upstream: vendor/better-auth/packages/better-auth/src/crypto/
// (buffer.ts, index.ts, jwt.ts, password.ts, random.ts).
//
// File map:
//   - buffer.go mirrors crypto/buffer.ts (constant-time comparison).
//   - jwt.go mirrors crypto/jwt.ts (HS256 sign/verify plus the JWE key
//     derivation and thumbprint helpers used by the session/account cookie
//     codecs).
//   - password.go mirrors crypto/password.ts (scrypt hash/verify).
//   - random.go mirrors crypto/random.ts (identifier and token randomness).
//   - symmetric.go mirrors crypto/index.ts (XChaCha20 symmetricEncrypt /
//     symmetricDecrypt with "$ba$" version envelopes).
//
// GO-ONLY EXTENSIONS (no upstream counterpart in
// packages/better-auth/src/crypto/): email-verification.go (email-token JWT
// helpers consumed by the API routes), jwe.go (portable HKDF/thumbprint
// helpers factored out of jwt.go), pkce.go (S256 challenge/verify; upstream
// threads PKCE through the OAuth2 flow in src/oauth2/state.ts and the
// provider layer — see ../../oauth2/utils.go), and token.go (legacy HMAC and
// AES-GCM token helpers kept as a migration bridge).
package crypto
