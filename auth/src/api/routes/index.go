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
//	account.go:              ListUserAccounts (listUserAccounts)
//	account_extra.go:        V1-EXCLUDED, not in tree (upstream account.ts
//	                         token/social legs: getAccessToken, refreshToken,
//	                         accountInfo, linkSocialAccount, unlinkAccount -
//	                         see auth/SCOPE.md; named here only so the catalog
//	                         covers every upstream owner)
//	delete-user-callback.go: DeleteUserCallback (deleteUserCallback)
//	email-verification.go:   SendVerificationEmail (sendVerificationEmail),
//	                         VerifyEmail (verifyEmail), VerifyEmailGet (verifyEmailGet)
//	error.go:                Error (auth-error-page)
//	ok.go:                   Ok (auth-ok)
//	password.go:             RequestPasswordReset (requestPasswordReset),
//	                         ResetPassword (resetPassword),
//	                         VerifyPassword (verifyPassword),
//	                         RequestPasswordResetCallback (resetPasswordCallback)
//	session.go:              GetSession (getSession, getSessionPost),
//	                         ListSessions (listUserSessions), RevokeSession (revokeSession),
//	                         RevokeSessions (revokeSessions),
//	                         RevokeOtherSessions (revokeOtherSessions),
//	                         UpdateSession (updateSession)
//	update-user.go:          UpdateUser (updateUser), ChangeEmail (changeEmail),
//	                         DeleteUser (deleteUser), ChangePassword (changePassword)
//	sign-in.go:              SignInEmail (signInEmail)
//	sign-out.go:             SignOut (signOut)
//	sign-up.go:              SignUpEmail (signUpWithEmailAndPassword)
//
//	V1 SCOPE (auth/SCOPE.md): social auth is explicitly out of scope.
//	`callback.go` is the exclusion stub for upstream `callback.ts`
//	(`CallbackOAuth`/`SignInSocial` never registered); `DeleteUserCallback`
//	(`/delete-user/callback`, owned by `update-user.ts`) lives in
//	`delete-user-callback.go`. The stale catalog line below is kept
//	for archaeology only and does not describe a present registrar:
//
// File structure is 1:1 with the upstream TS owners (B8 alignment):
// `password-extra.go` merged into `password.go`, `session-extra.go` +
// `session-c701.go` merged into `session.go`, the update-user family split
// out of `account.go` into `update-user.go` (ChangePassword moved from
// `password.go`). All same-package moves, no behavior change.
// Deliberately NOT mirrored: rate-limiter impl stays in the parent `api`
// package (folding it into `api/rate-limiter/` would cycle `api`<->child),
// and `crypto/symmetric.go` keeps its descriptive name instead of swapping
// with the package-doc `index.go`.
//
//// Go-only support files with no TS route counterpart (kept, not mapped):
//
//   - `generate-id.go` (model ID minting honoring `Advanced.Database.
//     GenerateID).
//   - `schema-fields.go` (schema field helpers; runtime counterpart work is
//     tracked under `src/db/schema.go` per the layout list).
//
// This file intentionally adds no new symbols: it is the upstream-shaped
// boundary documenting the catalog above.
