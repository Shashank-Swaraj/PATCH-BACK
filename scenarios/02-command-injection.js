/**
 * Scenario 2: Command Injection Sanitizer Swap (CWE-78)
 * Based on CVE-2021-21315
 */

export const commandInjectionScenario = {
  id: 'SCENARIO-02-COMMAND-INJECTION',
  name: 'System Diagnostic Ping Command Injection',
  cwe: 'CWE-78',
  sink: 'exec',
  guard: 'shellEscape',

  // 1. Buggy version: raw concatenation
  vulnerableCode: `
const { exec } = require('child_process');

function pingHost(host) {
  return exec('ping -c 1 ' + host); // VULNERABLE: Can inject ; rm -rf /
}
`,

  // 2. Fixed version: wrapped in shellEscape
  fixedCode: `
const { exec } = require('child_process');
const { shellEscape } = require('./security');

function pingHost(host) {
  // 🛡️ SECURITY GUARD:
  return exec(shellEscape(host));
}
`,

  // 3. Regression PR: String template modernization forgets escaping
  prCode: `
const { exec } = require('child_process');

// PR #520: "Modernized with ES6 template literal"
function pingHost(host) {
  return exec(\`ping -c 1 \${host}\`); // SINK called without shellEscape!
}
`,
  expectedResult: 'PROVEN_REGRESSION',
};

console.log('✅ Loaded Scenario 2: Command Injection (child_process.exec)');
