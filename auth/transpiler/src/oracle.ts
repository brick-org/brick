import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const source = fs.readFileSync(path.join(root, "vendor/better-auth/packages/better-auth/src/utils/boolean.ts"), "utf8");
const javascript = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const moduleURL = `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`;
const upstream: unknown = await import(moduleURL);
assert.ok(typeof upstream === "object" && upstream !== null && "toBoolean" in upstream);
const toBoolean = upstream.toBoolean;
assert.ok(typeof toBoolean === "function");
const cases = JSON.parse(fs.readFileSync(path.join(root, "auth/transpiler/fixtures/boolean.json"), "utf8")) as { value: unknown; expected: boolean }[];
for (const entry of cases) assert.equal(toBoolean(entry.value), entry.expected, `TypeScript source disagrees for ${JSON.stringify(entry.value)}`);
console.log(`verified ${cases.length} boolean fixtures against pinned TypeScript source`);

const metadataSource = fs.readFileSync(path.join(root, "vendor/better-auth/packages/better-auth/src/utils/hide-metadata.ts"), "utf8");
const metadataJS = ts.transpileModule(metadataSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const metadataModule: unknown = await import(`data:text/javascript;base64,${Buffer.from(metadataJS).toString("base64")}`);
assert.ok(typeof metadataModule === "object" && metadataModule !== null && "HIDE_METADATA" in metadataModule);
const metadataFixture: unknown = JSON.parse(fs.readFileSync(path.join(root, "auth/transpiler/fixtures/hide-metadata.json"), "utf8"));
assert.deepEqual(metadataModule.HIDE_METADATA, metadataFixture);
console.log("verified hide-metadata fixture against pinned TypeScript source");

const constantSourcePath = "vendor/better-auth/packages/better-auth/src/utils/constants.ts";
const constantSource = fs.readFileSync(path.join(root, constantSourcePath), "utf8");
const constantJS = ts.transpileModule(constantSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const constantModule: unknown = await import(`data:text/javascript;base64,${Buffer.from(constantJS).toString("base64")}`);
assert.ok(typeof constantModule === "object" && constantModule !== null && "DEFAULT_SECRET" in constantModule);
const constantFixture = JSON.parse(fs.readFileSync(path.join(root, "auth/transpiler/fixtures/constants.json"), "utf8")) as Record<string, string>;
assert.equal(constantModule.DEFAULT_SECRET, constantFixture.DEFAULT_SECRET);
console.log("verified constants fixture against pinned TypeScript source");

// Core-only for now: no plugin error-code fixtures. Plugin files will be
// re-added with their own oracle coverage once core is done.
