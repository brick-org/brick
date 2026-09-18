package routes

// --- Route catalog (upstream `src/api/routes/index.ts`) ---
//
// Upstream `routes/index.ts` re-exports every route module:
//
//	export * from "./account";
//	export * from "./callback";
//	export * from "./email-verification";
//	export * from "./error";
//	export * from "./ok";
//	export * from "./password";
//	export * from "./session";
//	export * from "./sign-in";
//	export * from "./sign-out";
//	export * from "./sign-up";
//	export * from "./update-session";
//	export * from "./update-user";
//
// The Go port keeps one package (`routes`) with one registrar function per
// endpoint. Registration order and every `OperationID` are owned by
// `api.Router` (`auth/src/api/index.go`), which gates each registrar behind
// `DisabledPaths`; this file changes neither. The catalog below pins the
// registrar -> OperationID mapping so renames are caught in review:
//
//	account.go:              ListUserAccounts (listUserAccounts), UpdateUser (updateUser),
//	                         ChangeEmail (changeEmail), DeleteUser (deleteUser)
//	account_extra.go:        GetAccessToken (getAccessToken), RefreshToken (refreshToken),
//	                         AccountInfo (accountInfo), LinkSocialAccount (linkSocialAccount),
//	                         UnlinkAccount (unlinkAccount)
//	delete-user-callback.go: DeleteUserCallback (deleteUserCallback)
//	email-verification.go:   SendVerificationEmail (sendVerificationEmail),
//	                         VerifyEmail (verifyEmail), VerifyEmailGet (verifyEmailGet)
//	error.go:                Error (auth-error-page)
//	ok.go:                   Ok (auth-ok)
//	password.go:             RequestPasswordReset (requestPasswordReset),
//	                         ResetPassword (resetPassword), ChangePassword (changePassword)
//	password-extra.go:       VerifyPassword (verifyPassword),
//	                         RequestPasswordResetCallback (resetPasswordCallback)
//	session.go:              GetSession (getSession, getSessionPost),
//	                         ListSessions (listUserSessions), RevokeSession (revokeSession)
//	session-extra.go:        RevokeSessions (revokeSessions),
//	                         RevokeOtherSessions (revokeOtherSessions),
//	                         UpdateSession (updateSession)
//	sign-in.go:              SignInEmail (signInEmail)
//	sign-out.go:             SignOut (signOut)
//	sign-up.go:              SignUpEmail (signUpWithEmailAndPassword)
//	social.go:               SignInSocial (signInSocial),
//	                         CallbackOAuth (oauthCallback, oauthCallbackPost)
//
// Intentional Go splits (same package, no import impact). Consolidation
// toward the single-file TS owners was evaluated and deliberately deferred:
// each `*_extra.go` / `session-c701.go` file compiles in the same `routes`
// package, so a merge would be behavior-neutral but high-churn, and the
// split keeps blame/review history stable. The TS ownership for future
// merges is:
//
//   - `account_extra.go` -> `account.ts` (token refresh, account info,
//     link/unlink social). Helpers (`decryptOAuthToken`, `loadUserAccount`,
//     `refreshAccountTokens`, `validAccountAccessToken`, `requireSessionUser`)
//     stay shared until a merge.
//   - `password-extra.go` -> `password.ts` (verify-password) and the
//     reset-password callback redirect (upstream `password.ts` callback
//     route). `resetTokenValid` / `appendRedirectQuery` stay shared.
//   - `session-c701.go` -> `session.ts` (cookie-cache issuance/refresh with
//     request context, upstream `session.ts` + `cookies/*` + JWT plugin
//     `cookie-cache.ts`). `session-extra.go` -> `session.ts` (revoke
//     variants) and `update-session.ts` (`UpdateSession`).
//   - `social.go` -> `sign-in.ts` (`SignInSocial`) + `callback.ts`
//     (`CallbackOAuth` GET+POST).
//   - `delete-user-callback.go` -> `callback.ts` side (`DeleteUserCallback`)
//     alongside `update-user.ts` ownership of `DeleteUser`.
//   - `hooks.go` -> `src/api/dispatch.go` + `src/api/to-auth-endpoints.go`
//     (hook pipeline, endpoint metadata, request-state stores, dynamic
//     baseURL); the Go-only Huma plumbing (`registerAuthOperation`,
//     `callRouteAPIErrorHandler`) stays here. The `api`-package facades
//     delegate to (never duplicate) these helpers because `api` already
//     imports `routes` and the reverse import would cycle.
//
// Go-only support files with no TS route counterpart (kept, not mapped):
//
//   - `generate-id.go` (model ID minting honoring `Advanced.Database.
//     GenerateID).
//   - `schema-fields.go` (schema field helpers; runtime counterpart work is
//     tracked under `src/db/schema.go` per the layout list).
//
// This file intentionally adds no new symbols: it is the upstream-shaped
// boundary documenting the catalog above.
