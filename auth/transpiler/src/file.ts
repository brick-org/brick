import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const files = [
	{ source: "vendor/better-auth/packages/better-auth/src/utils/boolean.ts", output: "auth/src/utils/boolean.gen.go", packageName: "utils" },
	{ source: "vendor/better-auth/packages/better-auth/src/utils/hide-metadata.ts", output: "auth/src/utils/hide_metadata.gen.go", packageName: "utils" },
	{ source: "vendor/better-auth/packages/better-auth/src/utils/constants.ts", output: "auth/src/utils/constants.gen.go", packageName: "utils" },
];
const pin = "5468e6bfcdff799848537cf5ad06ebab15aad9dd";
const coreErrorCodesPath = "vendor/better-auth/packages/core/src/utils/error-codes.ts";
const coreErrorCodesHash = "9d0cb94f3dbb9ac8edbffa27deee0401187a65a7b12d9e2fa38913d48cf1ced3";

type Expr = { kind: "parameter"; name: string } | { kind: "string"; value: string } |
	{ kind: "boolean"; value: boolean } | { kind: "strictEqual" | "or"; left: Expr; right: Expr };
type FunctionIR = { name: string; parameter: string; result: "bool"; body: Expr; line: number; column: number };
type ObjectIR = { kind: "stringMap" | "errorCodes"; name: string; fields: { name: string; value: string }[]; line: number; column: number };
type StringIR = { name: string; value: string; line: number; column: number };
type FileIR = { version: 3; source: string; packageName: string; sha256: string; coreErrorCodesHash?: string; functions: FunctionIR[]; objects: ObjectIR[]; strings: StringIR[] };

function unsupported(node: ts.Node, message: string): never {
	const file = node.getSourceFile();
	const { line, character } = file.getLineAndCharacterOfPosition(node.getStart(file));
	throw new Error(`${file.fileName}:${line + 1}:${character + 1}: unsupported ${ts.SyntaxKind[node.kind]}: ${message}`);
}

function expression(node: ts.Expression, parameter: string): Expr {
	if (ts.isIdentifier(node) && node.text === parameter) return { kind: "parameter", name: parameter };
	if (ts.isStringLiteral(node)) return { kind: "string", value: node.text };
	if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) {
		return { kind: "boolean", value: node.kind === ts.SyntaxKind.TrueKeyword };
	}
	if (ts.isParenthesizedExpression(node)) return expression(node.expression, parameter);
	if (ts.isBinaryExpression(node)) {
		const kind = node.operatorToken.kind === ts.SyntaxKind.BarBarToken ? "or" :
			node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ? "strictEqual" : undefined;
		if (!kind) unsupported(node.operatorToken, "add an operator lowering rule");
		const left = expression(node.left, parameter);
		const right = expression(node.right, parameter);
		if (kind === "strictEqual" && !(
			(left.kind === "parameter" && (right.kind === "string" || right.kind === "boolean")) ||
			(right.kind === "parameter" && (left.kind === "string" || left.kind === "boolean"))
		)) unsupported(node, "strict equality currently supports a parameter and a string or boolean literal");
		return { kind, left, right };
	}
	return unsupported(node, "add an expression lowering rule");
}

export function parseFile(text: string, filename: string, packageName = "utils", expectedCoreHash?: string): FileIR {
	const source = ts.createSourceFile(filename, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
	const diagnostics = (source as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics;
	if (diagnostics.length) {
		const issue = diagnostics[0]!;
		const { line, character } = source.getLineAndCharacterOfPosition(issue.start ?? 0);
		throw new Error(`${filename}:${line + 1}:${character + 1}: ${ts.flattenDiagnosticMessageText(issue.messageText, "\n")}`);
	}
	const functions: FunctionIR[] = [];
	const objects: ObjectIR[] = [];
	const strings: StringIR[] = [];
	let importsErrorCodes = false;
	for (const statement of source.statements) {
		if (!ts.isImportDeclaration(statement)) continue;
		const clause = statement.importClause;
		const moduleName = ts.isStringLiteral(statement.moduleSpecifier) ? statement.moduleSpecifier.text : "";
		if (clause?.isTypeOnly || clause?.name || !clause?.namedBindings || !ts.isNamedImports(clause.namedBindings) ||
			clause.namedBindings.elements.length !== 1 || clause.namedBindings.elements[0]?.isTypeOnly ||
			clause.namedBindings.elements[0]?.propertyName || clause.namedBindings.elements[0]?.name.text !== "defineErrorCodes" ||
			moduleName !== "@better-auth/core/utils/error-codes" || importsErrorCodes) {
			unsupported(statement, "only the defineErrorCodes intrinsic import is supported");
		}
		importsErrorCodes = true;
	}
	for (const statement of source.statements) {
		if (ts.isImportDeclaration(statement)) continue;
		if (ts.isVariableStatement(statement)) {
			if (statement.modifiers?.length !== 1 || statement.modifiers[0]?.kind !== ts.SyntaxKind.ExportKeyword ||
				(statement.declarationList.flags & ts.NodeFlags.Const) === 0 || statement.declarationList.declarations.length !== 1) {
				unsupported(statement, "expected one exported const declaration");
			}
			const declaration = statement.declarationList.declarations[0]!;
			const location = source.getLineAndCharacterOfPosition(statement.getStart(source));
			if (!ts.isIdentifier(declaration.name) || declaration.type || !declaration.initializer) unsupported(declaration, "expected an inferred exported const");
			if (ts.isStringLiteral(declaration.initializer)) {
				strings.push({ name: declaration.name.text, value: declaration.initializer.text, line: location.line + 1, column: location.character + 1 });
				continue;
			}
			let object: ts.ObjectLiteralExpression;
			let kind: ObjectIR["kind"];
			if (ts.isAsExpression(declaration.initializer) && ts.isTypeReferenceNode(declaration.initializer.type) &&
				ts.isIdentifier(declaration.initializer.type.typeName) && declaration.initializer.type.typeName.text === "const" &&
				!declaration.initializer.type.typeArguments && ts.isObjectLiteralExpression(declaration.initializer.expression)) {
				object = declaration.initializer.expression;
				kind = "stringMap";
			} else if (ts.isCallExpression(declaration.initializer) && ts.isIdentifier(declaration.initializer.expression) &&
				declaration.initializer.expression.text === "defineErrorCodes" && declaration.initializer.arguments.length === 1 &&
				ts.isObjectLiteralExpression(declaration.initializer.arguments[0])) {
				if (!importsErrorCodes) unsupported(declaration.initializer, "defineErrorCodes must be imported from @better-auth/core/utils/error-codes");
				object = declaration.initializer.arguments[0];
				kind = "errorCodes";
			} else {
				unsupported(declaration.initializer, "expected a string, an object followed by as const, or defineErrorCodes(object)");
			}
			const fields: ObjectIR["fields"] = [];
			for (const property of object.properties) {
				if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.name) || !ts.isStringLiteral(property.initializer)) {
					unsupported(property, "expected a property with an identifier key and string literal value");
				}
				const key = property.name.text;
				if (fields.some((field) => field.name === key)) unsupported(property, "duplicate object key");
				fields.push({ name: key, value: property.initializer.text });
			}
			objects.push({ kind, name: declaration.name.text, fields, line: location.line + 1, column: location.character + 1 });
			continue;
		}
		if (!ts.isFunctionDeclaration(statement) || !statement.name || !statement.body ||
			statement.modifiers?.length !== 1 || statement.modifiers[0]?.kind !== ts.SyntaxKind.ExportKeyword ||
			statement.asteriskToken || statement.typeParameters || statement.parameters.length !== 1) {
			unsupported(statement, "expected an exported function with one parameter");
		}
		const param = statement.parameters[0]!;
		if (!ts.isIdentifier(param.name) || param.dotDotDotToken || param.questionToken || param.initializer ||
			param.type?.kind !== ts.SyntaxKind.AnyKeyword || statement.type?.kind !== ts.SyntaxKind.BooleanKeyword ||
			statement.body.statements.length !== 1) {
			unsupported(statement, "expected (parameter: any): boolean with one return statement");
		}
		const returned = statement.body.statements[0]!;
		if (!ts.isReturnStatement(returned) || !returned.expression) unsupported(returned, "expected return expression");
		const location = source.getLineAndCharacterOfPosition(statement.getStart(source));
		if (functions.some((fn) => upper(fn.name) === upper(statement.name!.text))) unsupported(statement, "duplicate Go function name");
		functions.push({ name: statement.name.text, parameter: param.name.text, result: "bool",
			body: expression(returned.expression, param.name.text), line: location.line + 1, column: location.character + 1 });
	}
	if (!functions.length && !objects.length && !strings.length) unsupported(source, "file must contain an exported runtime declaration");
	if (objects.some((object) => object.kind === "errorCodes") && !expectedCoreHash) unsupported(source, "the defineErrorCodes intrinsic source hash must be verified");
	return { version: 3, source: filename, packageName, sha256: createHash("sha256").update(text).digest("hex"),
		coreErrorCodesHash: objects.some((object) => object.kind === "errorCodes") ? expectedCoreHash : undefined,
		functions, objects, strings };
}

function upper(name: string): string {
	return name[0]!.toUpperCase() + name.slice(1);
}

function goName(name: string): string {
	return upper(name.toLowerCase().replaceAll(/_([a-z])/g, (_match, char: string) => char.toUpperCase()));
}

function emitExpr(expr: Expr, parameter: string): string {
	switch (expr.kind) {
		case "parameter": return parameter;
		case "string": return JSON.stringify(expr.value);
		case "boolean": return String(expr.value);
		case "or": return `(${emitExpr(expr.left, parameter)} || ${emitExpr(expr.right, parameter)})`;
		case "strictEqual": {
			const literal = expr.left.kind === "string" || expr.left.kind === "boolean" ? expr.left : expr.right;
			const value = literal === expr.left ? expr.right : expr.left;
			if (value.kind !== "parameter" || (literal.kind !== "string" && literal.kind !== "boolean")) {
				throw new Error("unsupported IR: strict equality requires a parameter and a string or boolean literal");
			}
			const type = literal.kind === "string" ? "string" : "bool";
			return `(func() bool { v, ok := ${parameter}.(${type}); return ok && v == ${emitExpr(literal, parameter)} }())`;
		}
	}
}

export function emitFile(ir: FileIR): string {
	const functions = ir.functions.map((fn) => `// ${upper(fn.name)} transpiled from ${ir.source}:${fn.line}:${fn.column}.
func ${upper(fn.name)}(${fn.parameter} any) bool {
	return ${emitExpr(fn.body, fn.parameter)}
}`).join("\n\n");
	const objects = ir.objects.map((object) => `// ${goName(object.name)} transpiled from ${ir.source}:${object.line}:${object.column}.
var ${goName(object.name)} = ${object.kind === "errorCodes" ? "map[string]RawError" : "map[string]string"}{
${object.fields.map((field) => object.kind === "errorCodes" ? `\t${JSON.stringify(field.name)}: {Code: ${JSON.stringify(field.name)}, Message: ${JSON.stringify(field.value)}},` : `\t${JSON.stringify(field.name)}: ${JSON.stringify(field.value)},`).join("\n")}
}`);
	const stringConsts = ir.strings.map((value) => `// ${goName(value.name)} transpiled from ${ir.source}:${value.line}:${value.column}.
const ${goName(value.name)} = ${JSON.stringify(value.value)}`).join("\n\n");
	const code = `// Code generated by auth/transpiler; DO NOT EDIT.
// Source: ${ir.source}
// Source SHA-256: ${ir.sha256}
// IR version: ${ir.version}
${ir.coreErrorCodesHash ? `// Intrinsic defineErrorCodes SHA-256: ${ir.coreErrorCodesHash}\n` : ""}package ${ir.packageName}

${[functions, objects, stringConsts].filter(Boolean).join("\n\n")}
`;
	return execFileSync("gofmt", [], { input: code, encoding: "utf8" });
}

function main(): void {
	const mode = process.argv[2];
	if (mode !== "--write" && mode !== "--check") throw new Error("usage: file.js --write|--check");
	const commit = execFileSync("git", ["-C", path.join(root, "vendor/better-auth"), "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
	if (commit !== pin) throw new Error(`expected vendor/better-auth at ${pin}, got ${commit}`);
	const version = JSON.parse(fs.readFileSync(path.join(root, "vendor/better-auth/packages/better-auth/package.json"), "utf8")) as { version: string };
	if (version.version !== "1.7.5") throw new Error(`expected Better Auth v1.7.5, got ${version.version}`);
	const coreHash = createHash("sha256").update(fs.readFileSync(path.join(root, coreErrorCodesPath))).digest("hex");
	if (coreHash !== coreErrorCodesHash) throw new Error(`defineErrorCodes intrinsic changed: expected ${coreErrorCodesHash}, got ${coreHash}`);
	for (const file of files) {
		const ir = parseFile(fs.readFileSync(path.join(root, file.source), "utf8"), file.source, file.packageName,
			file.source.endsWith("/error-codes.ts") ? coreHash : undefined);
		const generated = emitFile(ir);
		const destination = path.join(root, file.output);
		if (mode === "--check") {
			if (!fs.existsSync(destination) || fs.readFileSync(destination, "utf8") !== generated) {
				throw new Error(`${file.output} is missing or stale; run pnpm run generate`);
			}
		} else {
			fs.mkdirSync(path.dirname(destination), { recursive: true });
			if (fs.existsSync(destination) && !fs.readFileSync(destination, "utf8").startsWith("// Code generated by auth/transpiler; DO NOT EDIT.")) {
				throw new Error(`refusing to overwrite non-generated file ${file.output}`);
			}
			fs.writeFileSync(destination, generated);
		}
		console.log(`${mode === "--write" ? "generated" : "verified"} ${file.output}`);
	}
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
