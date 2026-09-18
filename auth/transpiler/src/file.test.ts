import assert from "node:assert/strict";
import { test } from "node:test";
import { emitFile, parseFile } from "./file.js";

test("translates a whole file instead of recognizing a hardcoded function name", () => {
	const ir = parseFile('export function accepts(input: any): boolean { return input === "yes" || input === true; }', "example.ts");
	assert.equal(ir.version, 3);
	assert.equal(ir.functions[0]?.name, "accepts");
	const go = emitFile(ir);
	assert.match(go, /func Accepts\(input any\) bool/);
	assert.match(go, /input\.\(string\)/);
	assert.match(go, /input\.\(bool\)/);
});

test("translates an entire exported as-const object", () => {
	const ir = parseFile('export const SETTINGS = { scope: "server", mode: "strict" } as const;', "settings.ts");
	assert.deepEqual(ir.objects[0]?.fields, [{ name: "scope", value: "server" }, { name: "mode", value: "strict" }]);
	const go = emitFile(ir);
	assert.match(go, /var Settings = map\[string\]string\{/);
	assert.match(go, /"scope": "server"/);
});

test("translates string exports and the defineErrorCodes intrinsic", () => {
	const secret = parseFile('export const DEFAULT_SECRET = "secret-value";', "constants.ts");
	assert.equal(secret.strings[0]?.value, "secret-value");
	const errorCodes = parseFile(
		'import { defineErrorCodes } from "@better-auth/core/utils/error-codes"; export const ERROR_CODES = defineErrorCodes({ INVALID: "Invalid" });',
		"error-codes.ts",
		"types",
		"pinned-core-helper-hash",
	);
	assert.equal(errorCodes.objects[0]?.kind, "errorCodes");
	assert.match(emitFile(errorCodes), /map\[string\]RawError/);
	assert.throws(() => parseFile(
		'import { defineErrorCodes } from "@better-auth/core/utils/error-codes"; export const ERROR_CODES = defineErrorCodes({ INVALID: "Invalid" });',
		"error-codes.ts",
	), /intrinsic source hash must be verified/);
});

test("every unsupported declaration, statement and expression fails with a location", () => {
	for (const text of [
		"export const ignored = 1;",
		"export function f(x: any): boolean { if (x) return true; return false; }",
		"export function f(x: any): boolean { return x == true; }",
		"export function f(x: any): boolean { return unknown(x); }",
		"export function f(x: any): boolean { return x === x; }",
		"export const SETTINGS = { scope: 123 } as const;",
		"export const SETTINGS = { ...other } as const;",
		"export const SETTINGS = { scope: 'server' };",
		'import { other } from "unknown"; export const ERROR_CODES = other({ INVALID: "Invalid" });',
	]) {
		assert.throws(() => parseFile(text, "unsupported.ts"), /unsupported\.ts:\d+:\d+: unsupported/);
	}
	assert.throws(() => parseFile("export const x = 1", "unsupported.ts"), /unsupported\.ts:1:18: unsupported FirstLiteralToken/);
});
