/**
 * TEMPLATE: Copy this format for your scenarios (Suhani)
 */

export const scenario = {
  id: 'SCENARIO-ID-HERE',
  name: 'Vulnerability Name (e.g. Express Path Traversal)',
  cwe: 'CWE-Number (e.g. CWE-22)',
  sink: 'The dangerous function being called (e.g. sendFile)',
  guard: 'The safety check required (e.g. startsWith)',

  // Step 1: Write the original insecure code here
  vulnerableCode: `
    // TODO: Write vulnerable code snippet
  `,

  // Step 2: Write the secure patched code with the guard
  fixedCode: `
    // TODO: Write code with the security guard added
  `,

  // Step 3: Write the refactored PR that accidentally forgot the guard
  prCode: `
    // TODO: Write refactored PR code that forgets or bypasses the guard
  `,

  expectedResult: 'PROVEN_REGRESSION', // or 'SAFE_PASS'
};
