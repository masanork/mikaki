/** Compile exact product Agent SQL into an OP-owned capability catalog. */
import ts from 'typescript';
import { format } from 'prettier';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const files = ['store', 'oauth', 'attribute-proposals', 'record-proposals', 'model'].map((name) =>
  resolve(`crates/agent-worker/${name}.ts`),
);
const program = ts.createProgram(files, {
  target: ts.ScriptTarget.ESNext,
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
});
const checker = program.getTypeChecker();
type Scope = Map<ts.Symbol, string[]>;
function symbolOf(node: ts.Node) {
  let symbol = checker.getSymbolAtLocation(node);
  if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol;
}
function invoke(
  fn: ts.FunctionDeclaration | ts.ArrowFunction,
  args: ts.Expression[],
  scope: Scope,
): string[] {
  const next = new Map(scope);
  fn.parameters.forEach((parameter, index) => {
    const symbol = symbolOf(parameter.name);
    if (!symbol || !args[index]) throw new Error('Nonstatic SQL helper argument');
    next.set(symbol, values(args[index], scope));
  });
  const expression = ts.isBlock(fn.body!)
    ? fn.body!.statements.find(ts.isReturnStatement)?.expression
    : fn.body;
  if (!expression || ts.isBlock(expression))
    throw new Error('SQL helper requires one return expression');
  return values(expression, next);
}
function array(node: ts.Expression, scope: Scope): string[] {
  if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node))
    return array(node.expression, scope);
  if (ts.isArrayLiteralExpression(node))
    return node.elements.flatMap((element) =>
      ts.isSpreadElement(element) ? array(element.expression, scope) : values(element, scope),
    );
  if (ts.isIdentifier(node)) {
    const declaration = symbolOf(node)?.valueDeclaration;
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer)
      return array(declaration.initializer, scope);
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === 'map' &&
    ts.isArrowFunction(node.arguments[0])
  ) {
    const callback = node.arguments[0];
    return array(node.expression.expression, scope).flatMap((item) => {
      const next = new Map(scope);
      const symbol = callback.parameters[0] && symbolOf(callback.parameters[0].name);
      if (ts.isBlock(callback.body)) throw new Error('Nonstatic SQL array callback');
      if (symbol) next.set(symbol, [item]);
      return values(callback.body, next);
    });
  }
  throw new Error(`Nonstatic SQL array: ${node.getText()}`);
}
function values(node: ts.Expression, scope: Scope = new Map()): string[] {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return [node.text];
  if (ts.isParenthesizedExpression(node)) return values(node.expression, scope);
  if (ts.isConditionalExpression(node))
    return [...values(node.whenTrue, scope), ...values(node.whenFalse, scope)];
  if (ts.isTemplateExpression(node)) {
    let result = [node.head.text];
    for (const span of node.templateSpans)
      result = result.flatMap((prefix) =>
        values(span.expression, scope).map((value) => prefix + value + span.literal.text),
      );
    return result;
  }
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const method = node.expression.name.text;
    const target = node.expression.expression;
    if (method === 'join')
      return values(node.arguments[0], scope).map((separator) =>
        array(target, scope).join(separator),
      );
    if (method === 'replace' && node.arguments.length === 2) {
      const from = node.arguments[0];
      if (ts.isRegularExpressionLiteral(from)) {
        if (from.text !== '/authorization_details$/')
          throw new Error('Unsupported SQL helper pattern');
        return values(node.expression.expression, scope).flatMap((source) =>
          values(node.arguments[1], scope).map((to) =>
            source.replace(/authorization_details$/, to),
          ),
        );
      }
      return values(node.expression.expression, scope).flatMap((source) =>
        values(from, scope).flatMap((pattern) =>
          values(node.arguments[1], scope).map((to) => source.replace(pattern, to)),
        ),
      );
    }
  }
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
    const declaration = symbolOf(node.expression)?.valueDeclaration;
    if (declaration && ts.isFunctionDeclaration(declaration))
      return invoke(declaration, [...node.arguments], scope);
    if (
      declaration &&
      ts.isVariableDeclaration(declaration) &&
      declaration.initializer &&
      ts.isArrowFunction(declaration.initializer)
    )
      return invoke(declaration.initializer, [...node.arguments], scope);
  }
  if (ts.isIdentifier(node)) {
    const symbol = symbolOf(node);
    if (symbol && scope.has(symbol)) return scope.get(symbol)!;
    const declaration = symbol?.valueDeclaration;
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer)
      return values(declaration.initializer, scope);
  }
  throw new Error(`Nonstatic SQL: ${node.getText()}`);
}
const queries: Record<string, string> = {};
for (const file of files) {
  const source = program.getSourceFile(file)!;
  function visit(node: ts.Node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'prepare'
    ) {
      for (const sql of values(node.arguments[0])) {
        for (const mutation of sql.matchAll(
          /\b(?:INSERT(?: OR [A-Z]+)? INTO|UPDATE(?!\s+SET\b)|DELETE FROM)\s+([a-z_]+)/gi,
        )) {
          if (!mutation[1].startsWith('agent_'))
            throw new Error(`Agent cannot mutate OP-owned table: ${mutation[1]}`);
        }
        if (!/^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(sql) || sql.includes(';'))
          throw new Error('Only one catalogued domain statement is allowed: ' + sql.slice(0, 200));
        const id = createHash('sha256').update(sql).digest('hex');
        queries[id] = sql;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
}
const output = await format(
  `// Generated by scripts/build-service-catalog.ts; review every capability change.\nexport const agentQueries: Record<string, string> = ${JSON.stringify(Object.fromEntries(Object.entries(queries).sort()), null, 2)};\n`,
  { parser: 'typescript', singleQuote: true },
);
const destination = 'crates/worker/service/agent-catalog.ts';
if (process.argv.includes('--check')) {
  if ((await readFile(destination, 'utf8')) !== output)
    throw new Error('Agent capability catalog is stale; run node scripts/build-service-catalog.ts');
} else await writeFile(destination, output);
console.log(`Agent store: ${Object.keys(queries).length} static product statements`);
