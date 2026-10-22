/**
 * Scenario 1: Path Traversal in Express (CWE-22)
 * Based on CVE-2022-29244 / The Pitch Deck Case
 */

export const pathTraversalScenario = {
  id: 'SCENARIO-01-PATH-TRAVERSAL',
  name: 'Express File Server Path Traversal',
  cwe: 'CWE-22',
  sink: 'sendFile',
  guard: 'startsWith',

  // 1. Buggy version (2022): Hacker can access ../../../../etc/passwd
  vulnerableCode: `
const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

app.get('/f', (req, res) => {
  const p = path.join(root, req.query.p);
  res.sendFile(p); // VULNERABLE: No root containment check
});
`,

  // 2. Fixed version (2022): Adds startsWith guard
  fixedCode: `
const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

app.get('/f', (req, res) => {
  const p = path.resolve(root, req.query.p);
  // 🛡️ SECURITY GUARD:
  if (!p.startsWith(root)) {
    return res.status(403).send('Forbidden');
  }
  res.sendFile(p);
});
`,

  // 3. Regression PR (2024): Clean up / helper extraction bypasses guard
  prCode: `
const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

function sendAsset(res, filePath) {
  res.sendFile(filePath);
}

app.get('/f', (req, res) => {
  const p = path.resolve(root, req.query.p);
  if (!p.startsWith(root)) return res.status(403);
  sendAsset(res, p);
});

// PR #412 adds this new route: calls sendAsset without startsWith!
app.get('/asset', (req, res) => {
  sendAsset(res, req.query.p);
});
`,
  expectedResult: 'PROVEN_REGRESSION',
};

console.log('✅ Loaded Scenario 1: Path Traversal (Express sendFile)');
