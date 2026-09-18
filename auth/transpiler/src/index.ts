import * as fs from "node:fs";
import * as path from "node:path";
import { createHash as createSHA256 } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";

type SetRoleIR = {
	upstreamCommit: string;
	upstreamSourceHash: string;
	parseRoles: "array-join-comma-else-identity";
	path: string;
	method: "POST";
	requireHeaders: true;
	operationID: string;
	summary: string;
	description: string;
	body: {
		userID: "coerce-string";
		role: "string-or-string-array";
	};
};

const PINNED_COMMIT = "5468e6bfcdff799848537cf5ad06ebab15aad9dd";
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const sourceRelative = "vendor/better-auth/packages/better-auth/src/plugins/admin/routes.ts";
const outputRelative = "auth/src/plugins/admin/set_role.gen.go";

function fail(node: ts.Node | undefined, message: string): never {
	if (!node) throw new Error(message);
	const source = node.getSourceFile();
	const position = source.getLineAndCharacterOfPosition(node.getStart(source));
	throw new Error(`${source.fileName}:${position.line + 1}:${position.character + 1}: ${message}`);
}

function assert(condition: unknown, node: ts.Node | undefined, message: string): asserts condition {
	if (!condition) fail(node, message);
}

function prop(object: ts.ObjectLiteralExpression, name: string): ts.Expression {
	const found = object.properties.find((item): item is ts.PropertyAssignment =>
		ts.isPropertyAssignment(item) && ts.isIdentifier(item.name) && item.name.text === name,
	);
	assert(found, object, `expected property ${name}`);
	return found.initializer;
}

function stringLiteral(node: ts.Expression): string {
	assert(ts.isStringLiteral(node), node, "expected string literal");
	return node.text;
}

function identifier(node: ts.Expression, expected?: string): string {
	assert(ts.isIdentifier(node), node, "expected identifier");
	if (expected !== undefined) assert(node.text === expected, node, `expected identifier ${expected}`);
	return node.text;
}

function call(node: ts.Expression, receiver: string, method: string): ts.CallExpression {
	assert(ts.isCallExpression(node), node, `expected ${receiver}.${method}(...) call`);
	assert(ts.isPropertyAccessExpression(node.expression), node, `expected ${receiver}.${method}(...) call`);
	assert(ts.isIdentifier(node.expression.expression) && node.expression.expression.text === receiver, node, `expected receiver ${receiver}`);
	assert(node.expression.name.text === method, node, `expected method ${method}`);
	return node;
}

function unwrapMeta(node: ts.Expression): ts.Expression {
	let current = node;
	while (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression) && current.expression.name.text === "meta") {
		current = current.expression.expression;
	}
	return current;
}

function structuralMismatch(actual: ts.Node, expected: ts.Node, path = "root"): string | undefined {
	if (actual.kind !== expected.kind) return `${path}: ${ts.SyntaxKind[actual.kind]} != ${ts.SyntaxKind[expected.kind]}`;
	if (ts.isIdentifier(actual) && ts.isIdentifier(expected) && actual.text !== expected.text) return `${path}: identifier ${actual.text} != ${expected.text}`;
	if (ts.isLiteralExpression(actual as ts.Expression) && ts.isLiteralExpression(expected as ts.Expression) && (actual as ts.LiteralExpression).text !== (expected as ts.LiteralExpression).text) return `${path}: literal text differs`;
	const semanticChildren = (node: ts.Node): ts.Node[] => {
		const children: ts.Node[] = [];
		ts.forEachChild(node, (child) => { children.push(child); }, (nodes) => { children.push(...nodes); });
		return children;
	};
	const actualChildren = semanticChildren(actual);
	const expectedChildren = semanticChildren(expected);
	if (actualChildren.length !== expectedChildren.length) return `${path} ${ts.SyntaxKind[actual.kind]} (${JSON.stringify(actual.getText().slice(0, 70))}): child count ${actualChildren.length} != ${expectedChildren.length}`;
	for (let index = 0; index < actualChildren.length; index++) {
		const child = actualChildren[index];
		const counterpart = expectedChildren[index];
		if (!child || !counterpart) return `${path}.${index}: missing child`;
		const mismatch = structuralMismatch(child, counterpart, `${path}.${index}`);
		if (mismatch) return mismatch;
	}
	return undefined;
}

function assertNodeEquivalent(node: ts.Node, expectedText: string, label: string): void {
	const expectedSource = ts.createSourceFile(
		"expected.ts",
		`const __expected = ${expectedText};`,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
	const declaration = expectedSource.statements[0];
	assert(declaration && ts.isVariableStatement(declaration), node, `invalid internal ${label} AST fixture`);
	const variable = declaration.declarationList.declarations[0];
	assert(variable?.initializer, node, `invalid internal ${label} AST fixture`);
	let expected = variable.initializer;
	if (ts.isParenthesizedExpression(expected)) expected = expected.expression;
	const mismatch = structuralMismatch(node, expected);
	assert(!mismatch, node, `${label} changed at ${mismatch}; review and update the lowering before regenerating`);
}

function findVariable(source: ts.SourceFile, name: string): ts.VariableDeclaration {
	let result: ts.VariableDeclaration | undefined;
	const visit = (node: ts.Node): void => {
		if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) result = node;
		ts.forEachChild(node, visit);
	};
	visit(source);
	assert(result, source, `missing variable declaration ${name}`);
	return result;
}

function parseParseRoles(source: ts.SourceFile): SetRoleIR["parseRoles"] {
	const declaration = source.statements.find(
		(statement): statement is ts.FunctionDeclaration =>
			ts.isFunctionDeclaration(statement) && statement.name?.text === "parseRoles",
	);
	assert(declaration?.body, declaration, "missing parseRoles function body");
	assert(declaration.parameters.length === 1, declaration, "parseRoles must have one parameter");
	const parameter = declaration.parameters[0];
	assert(parameter && ts.isIdentifier(parameter.name) && parameter.name.text === "roles", parameter, "expected parameter roles");
	const type = parameter.type;
	assert(type && ts.isUnionTypeNode(type) && type.types.length === 2, parameter, "parseRoles parameter must be string | string[]");
	const hasString = type.types.some((member) => member.kind === ts.SyntaxKind.StringKeyword);
	const hasStringArray = type.types.some((member) => ts.isArrayTypeNode(member) && member.elementType.kind === ts.SyntaxKind.StringKeyword);
	assert(hasString && hasStringArray, type, "parseRoles type must be exactly string | string[]");
	const returned = declaration.body.statements.find(ts.isReturnStatement)?.expression;
	assert(returned && ts.isConditionalExpression(returned), declaration, "parseRoles must return a conditional expression");
	const condition = call(returned.condition, "Array", "isArray");
	assert(condition.arguments.length === 1 && ts.isIdentifier(condition.arguments[0]) && condition.arguments[0].text === "roles", condition, "expected Array.isArray(roles)");
	const joined = call(returned.whenTrue, "roles", "join");
	assert(joined.arguments.length === 1 && ts.isStringLiteral(joined.arguments[0]) && joined.arguments[0].text === ",", joined, "expected roles.join(',')");
	assert(ts.isIdentifier(returned.whenFalse) && returned.whenFalse.text === "roles", returned.whenFalse, "expected identity false branch");
	return "array-join-comma-else-identity";
}

function parseStringSchema(node: ts.Expression): boolean {
	node = unwrapMeta(node);
	return ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
		ts.isIdentifier(node.expression.expression) && node.expression.expression.text === "z" &&
		node.expression.name.text === "string" && node.arguments.length === 0;
}

function parseBodySchema(source: ts.SourceFile): SetRoleIR["body"] {
	const declaration = findVariable(source, "setRoleBodySchema");
	assert(declaration.initializer && ts.isCallExpression(declaration.initializer), declaration, "setRoleBodySchema must call z.object");
	const objectCall = declaration.initializer;
	assert(ts.isPropertyAccessExpression(objectCall.expression) && ts.isIdentifier(objectCall.expression.expression) && objectCall.expression.expression.text === "z" && objectCall.expression.name.text === "object", objectCall, "expected z.object schema");
	const fields = objectCall.arguments[0];
	assert(fields && ts.isObjectLiteralExpression(fields), objectCall, "expected z.object field literal");
	const userID = unwrapMeta(prop(fields, "userId"));
	assert(ts.isCallExpression(userID) && ts.isPropertyAccessExpression(userID.expression) && ts.isPropertyAccessExpression(userID.expression.expression), userID, "userId must use z.coerce.string()");
	assert(ts.isIdentifier(userID.expression.expression.expression) && userID.expression.expression.expression.text === "z" && userID.expression.expression.name.text === "coerce" && userID.expression.name.text === "string", userID, "userId must use z.coerce.string()");
	const role = unwrapMeta(prop(fields, "role"));
	assert(ts.isCallExpression(role) && ts.isPropertyAccessExpression(role.expression) && ts.isIdentifier(role.expression.expression) && role.expression.expression.text === "z" && role.expression.name.text === "union", role, "role must use z.union");
	const members = role.arguments[0];
	assert(members && ts.isArrayLiteralExpression(members) && members.elements.length === 2, role, "role union must contain string and string[]");
	assert(parseStringSchema(members.elements[0]!), members.elements[0], "first role union member must be z.string()");
	const arraySchema = members.elements[1]!;
	assert(ts.isCallExpression(arraySchema) && ts.isPropertyAccessExpression(arraySchema.expression) && ts.isIdentifier(arraySchema.expression.expression) && arraySchema.expression.expression.text === "z" && arraySchema.expression.name.text === "array" && arraySchema.arguments.length === 1 && parseStringSchema(arraySchema.arguments[0]!), arraySchema, "second role union member must be z.array(z.string())");
	return { userID: "coerce-string", role: "string-or-string-array" };
}

function parseEndpoint(source: ts.SourceFile): Pick<SetRoleIR, "path" | "method" | "requireHeaders" | "operationID" | "summary" | "description"> {
	const declaration = findVariable(source, "setRole");
	assert(declaration.initializer && ts.isArrowFunction(declaration.initializer), declaration, "setRole must be an arrow function");
	const outer = declaration.initializer.body;
	assert(ts.isCallExpression(outer), outer, "setRole must call createAuthEndpoint");
	assert(ts.isIdentifier(outer.expression) && outer.expression.text === "createAuthEndpoint", outer, "expected createAuthEndpoint");
	assert(outer.arguments.length === 3, outer, "expected endpoint path, options and handler");
	const routePath = stringLiteral(outer.arguments[0]!);
	const options = outer.arguments[1]!;
	assert(ts.isObjectLiteralExpression(options), options, "endpoint options must be an object literal");
	assertNodeEquivalent(options, `({
		method: "POST",
		body: setRoleBodySchema,
		requireHeaders: true,
		use: [adminMiddleware],
		metadata: {
			openapi: {
				operationId: "setUserRole",
				summary: "Set the role of a user",
				description: "Set the role of a user",
				responses: {
					200: {
						description: "User role updated",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										user: {
											$ref: "#/components/schemas/User",
										},
									},
								},
							},
						},
					},
				},
			},
			$Infer: {
				body: {} as {
					userId: string;
					role: InferAdminRolesFromOption<O> | InferAdminRolesFromOption<O>[];
				},
			},
		},
	})`, "setRole endpoint options");
	assert(stringLiteral(prop(options, "method")) === "POST", options, "setRole method must be POST");
	assert(identifier(prop(options, "body"), "setRoleBodySchema") === "setRoleBodySchema", options, "unexpected setRole body schema");
	assert(prop(options, "requireHeaders").kind === ts.SyntaxKind.TrueKeyword, options, "setRole must require headers");
	const metadata = prop(options, "metadata");
	assert(ts.isObjectLiteralExpression(metadata), metadata, "metadata must be object literal");
	const openapi = prop(metadata, "openapi");
	assert(ts.isObjectLiteralExpression(openapi), openapi, "openapi metadata must be object literal");
	const handler = outer.arguments[2]!;
	assert(ts.isArrowFunction(handler) && ts.isBlock(handler.body), handler, "setRole handler must be an arrow function with a block body");
	assertNodeEquivalent(handler, `(async (ctx) => {
		const canSetRole = hasPermission({
			userId: ctx.context.session.user.id,
			role: ctx.context.session.user.role,
			options: opts,
			permissions: { user: ["set-role"] },
		});
		if (!canSetRole) {
			throw APIError.from("FORBIDDEN", ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE);
		}
		const roles = opts.roles;
		if (roles) {
			const inputRoles = Array.isArray(ctx.body.role) ? ctx.body.role : [ctx.body.role];
			for (const role of inputRoles) {
				if (!roles[role as keyof typeof roles]) {
					throw APIError.from("BAD_REQUEST", ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE);
				}
			}
		}
		const isUserExist = await ctx.context.internalAdapter.findUserById(ctx.body.userId);
		if (!isUserExist) {
			throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
		}
		const updatedUser = await ctx.context.internalAdapter.updateUser(ctx.body.userId, {
			role: parseRoles(ctx.body.role),
		});
		return ctx.json({
			user: parseUserOutput(ctx.context.options, updatedUser) as UserWithRole,
		});
	})`, "setRole handler");
	return {
		path: routePath,
		method: "POST",
		requireHeaders: true,
		operationID: stringLiteral(prop(openapi, "operationId")),
		summary: stringLiteral(prop(openapi, "summary")),
		description: stringLiteral(prop(openapi, "description")),
	};
}

function goString(value: string): string {
	return JSON.stringify(value);
}

function emit(ir: SetRoleIR): string {
	return `// Code generated by auth/transpiler from ${sourceRelative}; DO NOT EDIT.
// Upstream commit: ${ir.upstreamCommit}
// Source SHA-256: ${ir.upstreamSourceHash}
package admin

import (
	"encoding/json"
	"strconv"
	"strings"
)

const (
	generatedSetRolePath = ${goString(ir.path)}
	generatedSetRoleMethod = ${goString(ir.method)}
	generatedSetRoleOperationID = ${goString(ir.operationID)}
	generatedSetRoleSummary = ${goString(ir.summary)}
	generatedSetRoleDescription = ${goString(ir.description)}
	generatedSetRoleRequiresHeaders = ${ir.requireHeaders}
)

// generatedSetRoleParseRoles is lowered from TS parseRoles() after Zod has
// validated string | string[]. It preserves role text exactly, as TS join does.
func generatedSetRoleParseRoles(value any) (string, bool) {
	switch roles := value.(type) {
	case string:
		return roles, true
	case []string:
		return strings.Join(roles, ","), true
	case []any:
		parts := make([]string, len(roles))
		for i, role := range roles {
			part, ok := role.(string)
			if !ok { return "", false }
			parts[i] = part
		}
		return strings.Join(parts, ","), true
	default:
		return "", false
	}
}

// generatedSetRoleRolesAllowed lowers the opts.roles iteration in routes.ts.
// A nil roles map is the absent option; an empty non-nil object is configured
// and therefore rejects every role, matching JavaScript object truthiness.
func generatedSetRoleRolesAllowed(value any, roles map[string]Role) bool {
	if roles == nil { return true }
	check := func(role string) bool { _, ok := roles[role]; return ok }
	switch input := value.(type) {
	case string:
		return check(input)
	case []string:
		for _, role := range input { if !check(role) { return false } }
		return true
	case []any:
		for _, item := range input {
			role, ok := item.(string)
			if !ok || !check(role) { return false }
		}
		return true
	default:
		return false
	}
}

// generatedSetRoleCoerceUserID lowers z.coerce.string() for JSON values.
func generatedSetRoleCoerceUserID(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "null", true
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return generatedSetRoleJSNumberString(v), true
	case json.Number:
		number, err := v.Float64()
		if err != nil { return "", false }
		return generatedSetRoleJSNumberString(number), true
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			if item == nil { continue }
			part, ok := generatedSetRoleCoerceUserID(item)
			if !ok { return "", false }
			parts[i] = part
		}
		return strings.Join(parts, ","), true
	case map[string]any:
		return "[object Object]", true
	default:
		return "", false
	}
}

// generatedSetRoleJSNumberString follows ECMAScript's fixed/exponential
// notation thresholds for finite JSON numbers (-6 <= exponent < 21).
func generatedSetRoleJSNumberString(value float64) string {
	if value == 0 { return "0" }
	if value != value { return "NaN" }
	if value > 1.7976931348623157e308 { return "Infinity" }
	if value < -1.7976931348623157e308 { return "-Infinity" }
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	parts := strings.SplitN(scientific, "e", 2)
	exponent, err := strconv.Atoi(parts[1])
	if err != nil { return scientific }
	if exponent >= -6 && exponent < 21 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	if exponent >= 0 { return parts[0] + "e+" + strconv.Itoa(exponent) }
	return parts[0] + "e" + strconv.Itoa(exponent)
}
`;
}

function transpile(): string {
	const upstreamDir = path.join(repoRoot, "vendor/better-auth");
	const upstreamCommit = execFileSync("git", ["-C", upstreamDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
	assert(upstreamCommit === PINNED_COMMIT, undefined, `vendor/better-auth HEAD is ${upstreamCommit}, expected ${PINNED_COMMIT}`);
	const packageJSON = JSON.parse(fs.readFileSync(path.join(upstreamDir, "packages/better-auth/package.json"), "utf8")) as { version: string };
	assert(packageJSON.version === "1.7.5", undefined, `better-auth package version is ${packageJSON.version}, expected 1.7.5`);
	const sourcePath = path.join(repoRoot, sourceRelative);
	const sourceText = fs.readFileSync(sourcePath, "utf8");
	const source = ts.createSourceFile(sourcePath, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
	const parseDiagnostics = (source as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics;
	assert(!parseDiagnostics.length, source, "TypeScript parser reported syntax errors");
	const parseRolesNode = source.statements.find(
		(statement): statement is ts.FunctionDeclaration => ts.isFunctionDeclaration(statement) && statement.name?.text === "parseRoles",
	);
	assert(parseRolesNode, source, "missing parseRoles function declaration");
	const schemaNode = findVariable(source, "setRoleBodySchema");
	const endpointNode = findVariable(source, "setRole");
	const generated = emit({
		upstreamCommit,
		upstreamSourceHash: hash([parseRolesNode.getText(source), schemaNode.getText(source), endpointNode.getText(source)].join("\0")),
		parseRoles: parseParseRoles(source),
		...parseEndpoint(source),
		body: parseBodySchema(source),
	});
	return execFileSync("gofmt", [], { input: generated, encoding: "utf8" });
}

function hash(text: string): string {
	return createSHA256("sha256").update(text).digest("hex");
}

const outputPath = path.join(repoRoot, outputRelative);
const output = transpile();
const mode = process.argv[2];
if (mode === "--write") {
	fs.writeFileSync(outputPath, output);
	console.log(`generated ${path.relative(repoRoot, outputPath)}`);
} else if (mode === "--check") {
	if (!fs.existsSync(outputPath) || fs.readFileSync(outputPath, "utf8") !== output) {
		console.error(`${outputRelative} is stale; run pnpm run generate`);
		process.exitCode = 1;
	} else {
		console.log(`${outputRelative} is up to date`);
	}
} else {
	console.error("usage: node dist/index.js --write|--check");
	process.exitCode = 2;
}
