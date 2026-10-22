import { parse } from '@babel/parser';
import traversePkg from '@babel/traverse';

// Support both ESM and CJS imports for Babel traverse
const traverse = traversePkg.default || traversePkg;

/**
 * Evaluates whether a dangerous sink (e.g., res.sendFile, exec)
 * is protected by a required defensive guard (e.g., startsWith, shellEscape).
 * 
 * @param {string} code - JavaScript source code of the file or PR
 * @param {string} sinkPattern - Name of sensitive function (e.g., 'sendFile', 'exec')
 * @param {string} guardPattern - Name of required safety check (e.g., 'startsWith', 'shellEscape')
 * @returns {object} Analysis result with verdict and line numbers
 */
export function checkSecurityInvariant(code, sinkPattern, guardPattern) {
  const ast = parse(code, {
    sourceType: 'unambiguous',
    plugins: ['jsx', 'typescript'],
  });

  const lines = code.split(/\r?\n/);
  const foundSinks = [];
  const foundGuards = [];

  // Step 1: Scan AST to find all Sinks and Guards
  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      let calleeName = '';

      if (callee.type === 'Identifier') {
        calleeName = callee.name;
      } else if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
        calleeName = callee.property.name;
      }

      // Did we find the dangerous sink?
      if (calleeName === sinkPattern || calleeName.endsWith('.' + sinkPattern)) {
        const line = path.node.loc ? path.node.loc.start.line : 1;
        const parentFunc = path.getFunctionParent();

        let funcName = 'top_level';
        let funcStart = 1;
        let funcEnd = lines.length;

        if (parentFunc && parentFunc.node.loc) {
          funcStart = parentFunc.node.loc.start.line;
          funcEnd = parentFunc.node.loc.end.line;
          if (parentFunc.node.id) {
            funcName = parentFunc.node.id.name;
          }
        }

        foundSinks.push({
          line,
          calleeName,
          funcName,
          funcStart,
          funcEnd,
          codeSnippet: lines[line - 1] ? lines[line - 1].trim() : '',
        });
      }
    },

    IfStatement(path) {
      const testLoc = path.node.test.loc;
      if (testLoc) {
        const condText = lines.slice(testLoc.start.line - 1, testLoc.end.line).join(' ');
        if (condText.includes(guardPattern)) {
          foundGuards.push({
            line: testLoc.start.line,
            condText: condText.trim(),
          });
        }
      }
    },
  });

  // Step 2: Check if each sink is guarded
  const violations = [];

  for (const sink of foundSinks) {
    // Check if there is a guard before the sink within the same function scope
    const isDirectlyGuarded = foundGuards.some(
      (g) => g.line < sink.line && g.line >= sink.funcStart && g.line <= sink.funcEnd
    );

    if (!isDirectlyGuarded) {
      violations.push({
        line: sink.line,
        sink: sinkPattern,
        missingGuard: guardPattern,
        functionName: sink.funcName,
        codeSnippet: sink.codeSnippet,
        explanation: `Dangerous sink '${sinkPattern}' at line ${sink.line} is called without required safety guard '${guardPattern}'.`,
      });
    }
  }

  const isVulnerable = violations.length > 0;

  return {
    verdict: isVulnerable ? 'PROVEN_REGRESSION' : 'SAFE_PASS',
    totalSinksFound: foundSinks.length,
    violationsCount: violations.length,
    violations,
  };
}
