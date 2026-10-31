
/**
 * Scenario 05: Timing Attack Regression
 *
 * CWE-208: Observable Timing Discrepancy
 *
 * Purpose:
 * Verify that PATCHBACK detects when a secure
 * cryptographic comparison is replaced by ===.
 */

export const scenario = {
  id: 'SCENARIO-05-TIMING-ATTACK',
  name: 'Timing Attack Guard Reversion',
  category: 'Cryptographic Timing Attack',
  cwe: 'CWE-208',
  sink: 'token === expectedToken',
  guard: 'crypto.timingSafeEqual',

  // Step 1: Original vulnerable code
  vulnerableCode: `
function verifyToken(token, expectedToken) {
  return token === expectedToken;
}
`,

  // Step 2: Historical security fix
  fixedCode: `
const crypto = require('node:crypto');

function verifyToken(token, expectedToken) {
  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expectedToken);

  if (tokenBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(tokenBuffer, expectedBuffer);
}
`,

  // Step 3: Incoming PR reverts the security fix
  prCode: `
function verifyToken(token, expectedToken) {
  // Regression: secure comparison was replaced.
  return token === expectedToken;
}
`,

  // Step 4: Expected analysis outcome
  expectedResult: 'PROVEN_REGRESSION',
};
