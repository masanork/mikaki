/** Resolve a restricted SQL expression language without executing product code. */
import { parse } from '@babel/parser';
import traverse, { type Binding, type NodePath } from '@babel/traverse';
import type { Program } from '@babel/types';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

type Context = Map<Binding, string[]>;
type Module = { path: NodePath<Program>; queries: NodePath[] };

export function staticSql(files: string[], read = (file: string) => readFileSync(file, 'utf8')) {
  const modules = new Map<string, Module>();
  const filenames = new WeakMap<Program, string>();
  function load(file: string): Module {
    file = resolve(file);
    const existing = modules.get(file);
    if (existing) return existing;
    const ast = parse(read(file), { sourceType: 'module', plugins: ['typescript'] });
    filenames.set(ast.program, file);
    let program: NodePath<Program> | undefined;
    const queries: NodePath[] = [];
    traverse(ast, {
      Program(path) {
        program = path;
      },
      CallExpression(path) {
        const callee = path.get('callee');
        if (
          callee.isMemberExpression() &&
          !callee.node.computed &&
          callee.get('property').isIdentifier({ name: 'prepare' })
        ) {
          const argument = path.get('arguments')[0];
          if (!argument) throw new Error('SQL prepare requires an argument');
          queries.push(argument);
        }
      },
    });
    if (!program) throw new Error('Missing module scope');
    const module = { path: program, queries };
    modules.set(file, module);
    return module;
  }
  function binding(path: NodePath): Binding {
    if (!path.isIdentifier()) throw new Error('Nonstatic SQL binding');
    let result = path.scope.getBinding(path.node.name);
    const seen = new Set<Binding>();
    while (result?.path.isImportSpecifier()) {
      if (seen.has(result)) throw new Error('Circular SQL import');
      seen.add(result);
      const declaration = result.path.parentPath;
      if (!declaration.isImportDeclaration() || !declaration.node.source.value.startsWith('.'))
        throw new Error('SQL imports must be local');
      const program = declaration.scope.getProgramParent().path;
      if (!program.isProgram()) throw new Error('Missing SQL module scope');
      const from = filenames.get(program.node)!;
      const target = load(
        resolve(dirname(from), declaration.node.source.value.replace(/\.js$/, '.ts')),
      );
      const imported = result.path.node.imported;
      const name = imported.type === 'Identifier' ? imported.name : imported.value;
      // Only direct named exports are supported; an unsupported re-export fails closed.
      const exported = target.path.get('body').some((item) => {
        if (!item.isExportNamedDeclaration() || item.node.source) return false;
        const value = item.get('declaration');
        if (value.isFunctionDeclaration()) return value.node.id?.name === name;
        if (value.isVariableDeclaration())
          return value.node.declarations.some(
            (declaration) => declaration.id.type === 'Identifier' && declaration.id.name === name,
          );
        return item.node.specifiers.some(
          (specifier) =>
            specifier.type === 'ExportSpecifier' &&
            (specifier.exported.type === 'Identifier'
              ? specifier.exported.name
              : specifier.exported.value) === name &&
            specifier.local.type === 'Identifier' &&
            specifier.local.name === name,
        );
      });
      if (!exported) throw new Error(`Unsupported SQL export: ${name}`);
      result = target.path.scope.getBinding(name);
    }
    if (!result) throw new Error(`Unbound SQL identifier: ${path.node.name}`);
    return result;
  }
  function invoke(fn: NodePath, args: NodePath[], context: Context): string[] {
    if (!fn.isFunctionDeclaration() && !fn.isArrowFunctionExpression())
      throw new Error('Nonstatic SQL function');
    const next = new Map(context);
    fn.get('params').forEach((parameter, index) => {
      if (!parameter.isIdentifier() || !args[index])
        throw new Error('Nonstatic SQL helper argument');
      next.set(binding(parameter), values(args[index], context));
    });
    const body = fn.get('body');
    if (!body.isBlockStatement()) return values(body, next);
    if (
      body
        .get('body')
        .some((statement) => !statement.isReturnStatement() && !statement.isVariableDeclaration())
    )
      throw new Error('Nonstatic SQL helper control flow');
    const returns = body.get('body').filter((statement) => statement.isReturnStatement());
    if (returns.length !== 1 || !returns[0].isReturnStatement())
      throw new Error('SQL helper requires one return expression');
    const value = returns[0].get('argument');
    if (!value.node) throw new Error('SQL helper requires a return value');
    return values(value as NodePath, next);
  }
  const evaluating = new Set<Binding>();
  function initializer(
    path: NodePath,
    context: Context,
    evaluate: (path: NodePath, context: Context) => string[],
  ): string[] {
    const variable = binding(path);
    if (context.has(variable)) return context.get(variable)!;
    if (!variable.constant || evaluating.has(variable) || !variable.path.isVariableDeclarator())
      throw new Error('Nonstatic or circular SQL variable');
    const init = variable.path.get('init');
    if (!init.node) throw new Error('Missing SQL initializer');
    evaluating.add(variable);
    try {
      return evaluate(init as NodePath, context);
    } finally {
      evaluating.delete(variable);
    }
  }
  function array(path: NodePath, context: Context): string[] {
    if (path.isTSAsExpression()) return array(path.get('expression'), context);
    if (path.isArrayExpression())
      return path.get('elements').flatMap((item) => {
        if (!item.node) throw new Error('Sparse SQL array');
        return item.isSpreadElement()
          ? array(item.get('argument'), context)
          : values(item as NodePath, context);
      });
    if (path.isIdentifier()) return initializer(path, context, array);
    if (path.isCallExpression()) {
      const callee = path.get('callee');
      const callback = path.get('arguments')[0];
      if (
        callee.isMemberExpression() &&
        !callee.node.computed &&
        callee.get('property').isIdentifier({ name: 'map' }) &&
        callback?.isArrowFunctionExpression()
      ) {
        const body = callback.get('body');
        if (body.isBlockStatement()) throw new Error('Nonstatic SQL array callback');
        return array(callee.get('object'), context).flatMap((item) => {
          const next = new Map(context);
          const parameter = callback.get('params')[0];
          if (parameter) next.set(binding(parameter), [item]);
          return values(body, next);
        });
      }
    }
    throw new Error(`Nonstatic SQL array: ${path.node.type}`);
  }
  function values(path: NodePath, context: Context = new Map()): string[] {
    if (path.isStringLiteral()) return [path.node.value];
    if (path.isTSAsExpression()) return values(path.get('expression'), context);
    if (path.isConditionalExpression())
      return [
        ...values(path.get('consequent'), context),
        ...values(path.get('alternate'), context),
      ];
    if (path.isTemplateLiteral()) {
      let result = [path.node.quasis[0].value.cooked!];
      path.get('expressions').forEach((expression, index) => {
        result = result.flatMap((prefix) =>
          values(expression, context).map(
            (value) => prefix + value + path.node.quasis[index + 1].value.cooked!,
          ),
        );
      });
      return result;
    }
    if (path.isCallExpression()) {
      const callee = path.get('callee');
      const args = path.get('arguments');
      if (callee.isMemberExpression() && !callee.node.computed) {
        const property = callee.get('property');
        const target = callee.get('object');
        if (property.isIdentifier({ name: 'join' }) && args.length === 1)
          return values(args[0], context).map((separator) =>
            array(target, context).join(separator),
          );
        if (property.isIdentifier({ name: 'replace' }) && args.length === 2) {
          const from = args[0];
          if (from.isRegExpLiteral()) {
            if (from.node.pattern !== 'authorization_details$' || from.node.flags)
              throw new Error('Unsupported SQL helper pattern');
            return values(target, context).flatMap((source) =>
              values(args[1], context).map((to) => source.replace(/authorization_details$/, to)),
            );
          }
          return values(target, context).flatMap((source) =>
            values(from, context).flatMap((pattern) =>
              values(args[1], context).map((to) => source.replace(pattern, to)),
            ),
          );
        }
      }
      if (callee.isIdentifier()) {
        const variable = binding(callee);
        if (!variable.constant || evaluating.has(variable))
          throw new Error('Nonstatic or circular SQL helper');
        const fn = variable.path;
        evaluating.add(variable);
        try {
          if (fn.isFunctionDeclaration()) return invoke(fn, args, context);
          if (fn.isVariableDeclarator() && fn.get('init').isArrowFunctionExpression())
            return invoke(fn.get('init') as NodePath, args, context);
        } finally {
          evaluating.delete(variable);
        }
      }
    }
    if (path.isIdentifier()) return initializer(path, context, values);
    throw new Error(`Nonstatic SQL: ${path.node.type}`);
  }
  return files.flatMap((file) => load(file).queries.flatMap((path) => values(path)));
}
