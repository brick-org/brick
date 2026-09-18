# Better Auth TypeScript → Go transpiler

Build the transpiler one complete source file at a time. Core-only for now:
it converts three complete files from the pinned Better Auth source into
executable Go:

- `utils/boolean.ts`
- `utils/hide-metadata.ts`
- `utils/constants.ts`

The compiler is still a small initial language subset, not a translation of all
Better Auth. Plugin files were removed to keep the review surface small and
will be re-added once core is done.

```sh
cd auth/transpiler
pnpm install --frozen-lockfile
pnpm run generate      # parse the pinned TS file and write Go
pnpm run check         # compare Go output; test unsupported syntax and TS oracle
cd ..
go test ./src/utils/...
```

The compiler uses TypeScript 5.8.3's AST, pinned in `pnpm-lock.yaml`. It
checks Better Auth v1.7.5 at commit
`5468e6bfcdff799848537cf5ad06ebab15aad9dd`. Output includes a source
SHA-256, IR version, and source location. `check` never writes to the tree;
`generate` refuses to overwrite a handwritten file. Only build-time tooling
requires Node: generated Go runs independently.

## Current language subset

- Exported functions with one `any` parameter and `boolean` result.
- A single `return` expression, parentheses, string/boolean literals,
  `===` between a parameter and a supported literal, and `||`.
- Exported string constants.
- Exported `const` object literals with identifier keys, string literal values,
  and `as const` (lowered to a Go map; TS `as const` is erased at runtime).
- A versioned in-memory expression/declaration/file IR and gofmt-formatted code.

Every other declaration, parameter, statement, operator, or expression causes
a source-located error. Add a lowering rule with tests before translating a
larger file. Fixtures are checked against the actual pinned TypeScript exports
(`src/oracle.ts`) and generated Go exports in `auth/src/utils/` tests.

The prior Admin `setRole` experiment remains available under
`pnpm run generate:set-role` and `pnpm run check:set-role`. It uses a separate
endpoint-specific generator (`src/index.ts`) and handwritten Go handler; it
does not represent the whole-file compiler.
