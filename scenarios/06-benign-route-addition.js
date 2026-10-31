
/**
 * Scenario 06: Benign Route Addition
 *
 * Purpose:
 * Verify that PATCHBACK does not flag an unrelated
 * health-check endpoint as a security regression.
 */

export const scenario = {
  id: 'SCENARIO-06-BENIGN-ROUTE-ADDITION',
  name: 'Benign Health Check Route Addition',
  category: 'Benign Control',
  cwe: 'N/A',
  sink: 'None - no new security-sensitive sink',
  guard: 'Existing security protections remain unchanged',

  // Step 1: Existing application code
  vulnerableCode: `
const express = require('express');
const app = express();

app.get('/status', (req, res) => {
  res.json({ status: 'running' });
});
`,

  // Step 2: Existing application state
  // No security fix is needed for this benign control.
  fixedCode: `
const express = require('express');
const app = express();

app.get('/status', (req, res) => {
  res.json({ status: 'running' });
});
`,

  // Step 3: Incoming PR adds an unrelated health endpoint
  prCode: `
const express = require('express');
const app = express();

app.get('/status', (req, res) => {
  res.json({ status: 'running' });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime()
  });
});
`,

  // Step 4: Expected analysis outcome
  expectedResult: 'SAFE_PASS',
};
