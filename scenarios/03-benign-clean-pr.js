/**
 * Scenario 3: Benign Clean PR (Zero False Alarm Control Test)
 * Shows a maintainer renaming variables and adding comments without removing guards.
 */

export const benignScenario = {
  id: 'SCENARIO-03-BENIGN-CLEANUP',
  name: 'Benign Code Cleanup & Renaming',
  cwe: 'None',
  sink: 'sendFile',
  guard: 'startsWith',

  prCode: `
const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

// Cleaned up parameter names and added helpful logging
app.get('/f', (request, response) => {
  console.log('Serving static file request');
  const resolvedPath = path.resolve(root, request.query.p);
  
  // Guard is preserved and intact:
  if (!resolvedPath.startsWith(root)) {
    return response.status(403).send('Forbidden');
  }
  
  response.sendFile(resolvedPath);
});
`,
  expectedResult: 'SAFE_PASS',
};

console.log('✅ Loaded Scenario 3: Benign Clean PR (Zero False Alarms)');
