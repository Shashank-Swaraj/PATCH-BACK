import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { ParsedFile } from './parser.js';

// Resolve CJS/ESM interop
const runTraverse: any = (traverse as any).default || traverse;

export interface SinkMatch {
  node: t.CallExpression;
  line: number;
  column: number;
  calleeName: string;
  enclosingFunctionName?: string;
  scopeStartLine: number;
  scopeEndLine: number;
  argumentsText: string[];
}

export interface GuardMatch {
  node: t.IfStatement | t.ConditionalExpression | t.CallExpression;
  line: number;
  conditionText: string;
  hasEarlyExit: boolean;
  enclosingFunctionName?: string;
  scopeStartLine: number;
  scopeEndLine: number;
}

/**
 * Checks if an AST node string representation matches a pattern (e.g. "res.sendFile" or "sendFile")
 */
export function matchesPattern(callee: t.Expression | t.V8IntrinsicIdentifier, pattern: string): boolean {
  if (t.isIdentifier(callee)) {
    return callee.name === pattern || pattern.endsWith('.' + callee.name);
  }

  if (t.isMemberExpression(callee)) {
    const parts: string[] = [];
    let current: t.Expression = callee;

    while (t.isMemberExpression(current)) {
      if (t.isIdentifier(current.property)) {
        parts.unshift(current.property.name);
      }
      current = current.object;
    }
    if (t.isIdentifier(current)) {
      parts.unshift(current.name);
    }

    const full = parts.join('.');
    return full === pattern || full.endsWith(pattern) || pattern.endsWith(parts[parts.length - 1] ?? '');
  }

  return false;
}

/**
 * Find all sink calls in a parsed file.
 */
export function findSinks(parsedFile: ParsedFile, sinkPattern: string): SinkMatch[] {
  const matches: SinkMatch[] = [];

  runTraverse(parsedFile.ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      if (matchesPattern(path.node.callee, sinkPattern)) {
        const line = path.node.loc?.start.line ?? 1;
        const column = path.node.loc?.start.column ?? 0;

        let enclosingFunctionName: string | undefined;
        let scopeStartLine = 1;
        let scopeEndLine = parsedFile.lines.length;

        const parentFunc = path.getFunctionParent();
        if (parentFunc && parentFunc.node.loc) {
          scopeStartLine = parentFunc.node.loc.start.line;
          scopeEndLine = parentFunc.node.loc.end.line;

          if (t.isFunctionDeclaration(parentFunc.node) && parentFunc.node.id) {
            enclosingFunctionName = parentFunc.node.id.name;
          } else if (t.isVariableDeclarator(parentFunc.parent) && t.isIdentifier(parentFunc.parent.id)) {
            enclosingFunctionName = parentFunc.parent.id.name;
          }
        }

        const argsText = path.node.arguments.map((arg: any) => {
          if (arg.loc) {
            return parsedFile.lines.slice(arg.loc.start.line - 1, arg.loc.end.line).join(' ').trim();
          }
          return '';
        });

        matches.push({
          node: path.node,
          line,
          column,
          calleeName: sinkPattern,
          enclosingFunctionName,
          scopeStartLine,
          scopeEndLine,
          argumentsText: argsText,
        });
      }
    },
  });

  return matches;
}

/**
 * Find all guards matching a substring/pattern in a parsed file.
 */
export function findGuards(parsedFile: ParsedFile, guardPattern: string): GuardMatch[] {
  const matches: GuardMatch[] = [];

  runTraverse(parsedFile.ast, {
    IfStatement(path: NodePath<t.IfStatement>) {
      const loc = path.node.loc;
      const testLoc = path.node.test.loc;
      const conditionText = testLoc
        ? parsedFile.lines.slice(testLoc.start.line - 1, testLoc.end.line).join(' ').trim()
        : '';

      if (conditionText.includes(guardPattern)) {
        let hasEarlyExit = false;
        path.get('consequent').traverse({
          ReturnStatement() {
            hasEarlyExit = true;
          },
          ThrowStatement() {
            hasEarlyExit = true;
          },
        });

        let enclosingFunctionName: string | undefined;
        let scopeStartLine = 1;
        let scopeEndLine = parsedFile.lines.length;

        const parentFunc = path.getFunctionParent();
        if (parentFunc && parentFunc.node.loc) {
          scopeStartLine = parentFunc.node.loc.start.line;
          scopeEndLine = parentFunc.node.loc.end.line;

          if (t.isFunctionDeclaration(parentFunc.node) && parentFunc.node.id) {
            enclosingFunctionName = parentFunc.node.id.name;
          }
        }

        matches.push({
          node: path.node,
          line: loc?.start.line ?? 1,
          conditionText,
          hasEarlyExit,
          enclosingFunctionName,
          scopeStartLine,
          scopeEndLine,
        });
      }
    },
  });

  return matches;
}
