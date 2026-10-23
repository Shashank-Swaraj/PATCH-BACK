
/**
 * Scenario 02: Command Injection Regression
 *
 * OWASP Top 10:2025 — A05: Injection
 * CWE-78: Improper Neutralization of Special Elements
 * used in an OS Command
 *
 * Purpose:
 * Detect a refactor that removes shell escaping from
 * a command-execution path.
 */

export const scenario = {
  id: 'SCENARIO-02-COMMAND-INJECTION',
  name: 'Command Injection Regression',
  cwe: 'CWE-78',
  sink: 'child_process.exec',
  guard: 'shellEscape(host)',

  // Step 1: Original vulnerable code
  vulnerableCode: `
    const { exec } = require('child_process');

    function pingHost(host) {
      exec('ping ' + host);
    }
  `,

  // Step 2: Historical security fix
  fixedCode: `
    const { exec } = require('child_process');

    function shellEscape(host) {
      // Illustrative placeholder for a vetted escaping routine.
      return escapeShellArgument(host);
    }

    function pingHost(host) {
      exec('ping ' + shellEscape(host));
    }
  `,

  // Step 3: Regression introduced by a refactor
  prCode: `
    const { exec } = require('child_process');

    function pingHost(host) {
      // Refactor uses a template literal but loses shell escaping.
      exec(\`ping \${host}\`);
    }
  `,

  expectedResult: 'PROVEN_REGRESSION',
};
