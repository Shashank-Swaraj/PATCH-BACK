import { parse } from '@babel/parser';
import traversePkg from '@babel/traverse';

const traverse = traversePkg.default || traversePkg;

/**
 * Core Security Invariant Checker
 * Assigned to: Lead (You)
 * 
 * Your Goal:
 * 1. Parse the given JavaScript code into an Abstract Syntax Tree (AST).
 * 2. Find any calls to the dangerous sink (e.g. 'sendFile', 'exec').
 * 3. Verify if that call is protected by the required guard (e.g. 'startsWith', 'shellEscape').
 * 4. Return an alert if the guard is missing or bypassed!
 */
export function checkSecurityInvariant(code, sinkPattern, guardPattern) {
  // TODO: Build your AST reachability check here
  const ast = parse(code, {
    sourceType: 'unambiguous',
    plugins: ['jsx', 'typescript'],
  });

  const lines = code.split(/\r?\n/);
  const foundSinks = [];
  const foundGuards = [];

  traverse(ast, {
    // TODO: Detect calls to sinkPattern
    CallExpression(path) {
      // Your code here
    },
    // TODO: Detect if checks containing guardPattern
    IfStatement(path) {
      // Your code here
    },
  });

  // Return the analysis verdict
  return {
    verdict: 'SAFE_PASS', // or 'PROVEN_REGRESSION'
    violations: [],
  };
}
