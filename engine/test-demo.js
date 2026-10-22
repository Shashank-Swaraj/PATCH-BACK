import { checkSecurityInvariant } from './checker.js';

// The refactored PR code (from the pitch deck slide)
const prCode = `
const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

// PR #412: "Clean up - extract sendAsset helper"
function sendAsset(res, filePath) {
  res.sendFile(filePath); // SINK: called directly without startsWith guard!
}

// Old route (still has guard)
app.get('/f', (req, res) => {
  const p = path.resolve(root, req.query.p);
  if (!p.startsWith(root)) return res.status(403);
  sendAsset(res, p);
});

// New route (BYPASS: skips guard!)
app.get('/asset', (req, res) => {
  sendAsset(res, req.query.p);
});
`;

console.log('🔍 PATCHBACK Engine: Scanning PR #412 for Security Regressions...\n');

const startTime = performance.now();
const result = checkSecurityInvariant(prCode, 'sendFile', 'startsWith');
const latency = (performance.now() - startTime).toFixed(2);

console.log(`⏱️ Analysis Time: ${latency}ms`);
console.log(`🛡️ Verdict:      ${result.verdict}\n`);

if (result.verdict === 'PROVEN_REGRESSION') {
  console.log('🚨 SECURITY REGRESSION DETECTED:');
  for (const v of result.violations) {
    console.log(`  --> [Line ${v.line}] in function '${v.functionName}':`);
    console.log(`      Code: "${v.codeSnippet}"`);
    console.log(`      Reason: ${v.explanation}`);
  }
} else {
  console.log('✅ PASS: All required security invariants are preserved.');
}
