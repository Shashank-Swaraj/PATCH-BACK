import { parse } from '@babel/parser';
import traversePkg from '@babel/traverse';

const traverse = traversePkg.default || traversePkg;

/**
 * Core Security Invariant Checker
 * Detects whether dangerous sinks are dominated by security guards.
 */
export function checkSecurityInvariant(code, sinkPattern, guardPattern) {
  const startTime = performance.now();

  const ast = parse(code, {
    sourceType: 'unambiguous',
    plugins: ['jsx', 'typescript'],
  });

  const violations = [];

  // Helper to extract clean name from a callee (e.g., "res.sendFile" or "exec")
  function getCalleeName(callee) {
    if (callee.type === 'Identifier') return callee.name;
    if (callee.type === 'MemberExpression') {
      const obj = callee.object.name || (callee.object.property ? callee.object.property.name : '');
      const prop = callee.property.name || '';
      return obj ? `${obj}.${prop}` : prop;
    }
    return '';
  }

  // Helper to check if a snippet of code or AST node contains the guard pattern
  function nodeMatchesGuard(node) {
    if (!node) return false;
    const nodeCode = code.slice(node.start, node.end);
    // Matches guard by identifier (e.g., "shellEscape") or member call (e.g., "startsWith")
    const cleanGuard = guardPattern.replace(/[()]/g, '').split('.')[0];
    return nodeCode.includes(cleanGuard) || nodeCode.includes(guardPattern);
  }

  traverse(ast, {
    CallExpression(path) {
      const calleeName = getCalleeName(path.node.callee);

      // Check if this call is the dangerous sink
      const isSink =
        calleeName === sinkPattern ||
        calleeName.endsWith(`.${sinkPattern}`) ||
        sinkPattern.endsWith(calleeName);

      if (!isSink) return;

      const sinkLine = path.node.loc?.start?.line ?? 1;
      let isGuarded = false;

      // 1. Check if any argument directly uses the guard (e.g., exec('ping ' + shellEscape(host)))
      for (const arg of path.node.arguments) {
        if (nodeMatchesGuard(arg)) {
          isGuarded = true;
          break;
        }
      }

      // 2. Check if the sink is inside an IfStatement or block that checks the guard
      let currentPath = path;
      while (currentPath && currentPath.parentPath) {
        if (currentPath.parentPath.isIfStatement()) {
          const ifNode = currentPath.parentPath.node;
          if (nodeMatchesGuard(ifNode.test)) {
            isGuarded = true;
            break;
          }
        }
        currentPath = currentPath.parentPath;
      }

      // 3. Check if the enclosing function or scope has an early guard check (e.g., if (!startsWith) return 403)
      const enclosingFunction = path.getFunctionParent();
      if (!isGuarded && enclosingFunction) {
        const fnBody = enclosingFunction.node.body;
        if (fnBody && fnBody.body && Array.isArray(fnBody.body)) {
          for (const stmt of fnBody.body) {
            // If the guard appears in a statement before our sink
            if (stmt.end <= path.node.start && nodeMatchesGuard(stmt)) {
              isGuarded = true;
              break;
            }
          }
        }
      }

      // If no guard protects this dangerous sink, flag it as a violation!
      if (!isGuarded) {
        violations.push({
          line: sinkLine,
          sink: calleeName,
          reason: `Dangerous sink '${calleeName}' invoked without historical security guard '${guardPattern}'`,
        });
      }
    },
  });

  const latencyMs = Number((performance.now() - startTime).toFixed(2));

  return {
    verdict: violations.length > 0 ? 'PROVEN_REGRESSION' : 'SAFE_PASS',
    violations,
    latencyMs,
  };
}