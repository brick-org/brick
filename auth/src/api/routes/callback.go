package routes

// --- callback.ts (v1-excluded) ---
//
// Upstream `src/api/routes/callback.ts` owns the social OAuth callback
// (`CallbackOAuth` GET+POST) and `DeleteUserCallback` sits alongside
// `update-user.ts` ownership of `DeleteUser`.
//
// V1 scope (auth/SCOPE.md) excludes all social auth: there is no
// `SignInSocial`/`CallbackOAuth` registrar in this tree, and these paths are
// never registered (`/sign-in/social`, `/callback/{provider}`).
// `DeleteUserCallback` (`/delete-user/callback`) IS in v1 scope and lives in
// `delete-user-callback.go` (owned by `update-user.ts`).
//
// This file exists so the 1:1 TS→Go file map has no phantom entries: every
// upstream route module has a named Go counterpart, even when the counterpart
// is an explicit exclusion stub. It intentionally adds no symbols.
//
// Upstream TypeScript names: CallbackOAuth (excluded), SignInSocial (excluded).
