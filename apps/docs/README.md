# Brick Docs

Documentation site for [Brick](https://github.com/brick-org/brick) — built with
[TanStack Start](https://tanstack.com/start) + [Fumadocs](https://fumadocs.dev).

## Develop

```bash
cd apps/docs
bun install
bun run dev      # http://localhost:3000
```

## Checks

```bash
bun run types:check
bun run build
```

## Content

MDX pages live in `content/docs/` (navigation via `meta.json` files).
Site shell: `src/routes/` (`__root.tsx`, `index.tsx`, `docs/$.tsx`),
shared layout: `src/lib/layout.shared.tsx` + `src/lib/shared.ts`
(app name, GitHub links).
