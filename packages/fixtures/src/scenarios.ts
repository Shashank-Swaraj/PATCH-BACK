import { AdvisoryRecord } from '@patchback/core';
import { SecurityInvariant } from '@patchback/core';

export interface BenchmarkScenario {
  id: string;
  name: string;
  category: string;
  cwe: string;
  description: string;
  advisory: AdvisoryRecord;
  invariant: SecurityInvariant;
  vulnerableCode: string;
  fixedCode: string;
  prDiff: string;
  prCode: string;
  expectedVerdict: 'PROVEN' | 'LIKELY' | 'REVIEW' | 'BENIGN';
  whyItMatters: string;
}

export const BENCHMARK_SCENARIOS: BenchmarkScenario[] = [
  {
    id: 'cve-2022-path-traversal',
    name: 'Express Path Traversal (The Pitch Deck Case)',
    category: 'Path Traversal',
    cwe: 'CWE-22',
    description: 'Path traversal in static file serving route allowed unauthorized file read.',
    whyItMatters: 'Demonstrates Guard Bypass regression when code is refactored into a helper function (regreSSHion pattern).',
    advisory: {
      id: 'GHSA-2022-29244',
      title: 'Path Traversal Arbitrary File Read in Static Server',
      description: 'Lack of root boundary validation allowed attackers to escape root via ../ sequences.',
      cwe: 'CWE-22',
      severity: 'HIGH',
      affectedPackage: 'serve-static-core',
      affectedVersions: '< 2.0.0',
      patchedVersions: '>= 2.0.0',
      fixCommitSha: '7a9c8f1',
      patchDiff: `@@ -8,3 +8,4 @@
 const p = path.resolve(root, q.query.p);
+if (!p.startsWith(root)) return r.status(403);
 r.sendFile(p);`,
      discoveredAt: '2022-06-15',
    },
    invariant: {
      id: 'INV-GHSA-2022-29244-01',
      advisoryId: 'GHSA-2022-29244',
      packageName: 'serve-static-core',
      createdAt: '2022-06-16T10:00:00Z',
      type: 'GUARD_DOMINATES',
      params: {
        source: 'q.query.p',
        sink: 'r.sendFile',
        guard: 'startsWith(root)',
      },
      vulnerabilityType: 'CWE-22',
      fixCommitSha: '7a9c8f1',
      rationale: 'Guard required to stop directory traversal escaping root directory',
      enabled: true,
    },
    vulnerableCode: `const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

app.get('/f', (q, r) => {
  const p = path.join(root, q.query.p);
  r.sendFile(p);
});`,
    fixedCode: `const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

app.get('/f', (q, r) => {
  const p = path.resolve(root, q.query.p);
  if (!p.startsWith(root)) {
    return r.status(403).send('Forbidden');
  }
  r.sendFile(p);
});`,
    prDiff: `@@ -10,3 +10,8 @@
+function sendAsset(r, p) {
+  r.sendFile(p);
+}
+app.get('/asset', (q, r) =>
+  sendAsset(r, q.query.p));`,
    prCode: `const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

// PR #412 "extract helper"
function sendAsset(r, p) {
  r.sendFile(p);
}

app.get('/f', (q, r) => {
  const p = path.resolve(root, q.query.p);
  if (!p.startsWith(root)) return r.status(403);
  sendAsset(r, p);
});

app.get('/asset', (q, r) =>
  sendAsset(r, q.query.p)
);`,
    expectedVerdict: 'PROVEN',
  },

  {
    id: 'cve-2021-command-injection',
    name: 'System Command Injection Sanitizer Swap',
    category: 'Command Injection',
    cwe: 'CWE-78',
    description: 'Direct concatenation into exec() allowed remote code execution via semicolon commands.',
    whyItMatters: 'Demonstrates Sanitizer Swap regression when an engineer swaps or forgets shell escaping.',
    advisory: {
      id: 'GHSA-2021-21315',
      title: 'Command Injection via Unsanitized Network Ping Host',
      description: 'Host input was concatenated into shell command without validation or escaping.',
      cwe: 'CWE-78',
      severity: 'CRITICAL',
      affectedPackage: 'system-diag-utils',
      affectedVersions: '< 1.4.0',
      patchedVersions: '>= 1.4.0',
      fixCommitSha: '4c8e1a2',
      patchDiff: `@@ -4,2 +4,2 @@
-exec('ping -c 1 ' + host);
+exec('ping -c 1 ' + shellEscape(host));`,
      discoveredAt: '2021-03-12',
    },
    invariant: {
      id: 'INV-GHSA-2021-21315-01',
      advisoryId: 'GHSA-2021-21315',
      packageName: 'system-diag-utils',
      createdAt: '2021-03-13T10:00:00Z',
      type: 'SANITIZER_SWAP',
      params: {
        sink: 'exec',
        requiredSanitizer: 'shellEscape',
        targetArgumentIndex: 0,
      },
      vulnerabilityType: 'CWE-78',
      fixCommitSha: '4c8e1a2',
      rationale: 'Commands passed to child_process.exec MUST use shellEscape',
      enabled: true,
    },
    vulnerableCode: `const { exec } = require('child_process');

function pingHost(host) {
  return exec('ping -c 1 ' + host);
}`,
    fixedCode: `const { exec } = require('child_process');
const { shellEscape } = require('./security');

function pingHost(host) {
  return exec(shellEscape(host));
}`,
    prDiff: `@@ -4,2 +4,2 @@
-  return exec(shellEscape(host));
+  return exec('ping -c 1 ' + host);`,
    prCode: `const { exec } = require('child_process');

// PR #520 "Modernize ping utility with string template"
function pingHost(host) {
  return exec('ping -c 1 ' + host);
}`,
    expectedVerdict: 'PROVEN',
  },

  {
    id: 'cve-2020-prototype-pollution',
    name: 'Prototype Pollution Blacklist Guard Removal',
    category: 'Prototype Pollution',
    cwe: 'CWE-1321',
    description: 'Object key assignment allowed overriding Object.prototype via __proto__ and constructor.',
    whyItMatters: 'Demonstrates Guard Removal when refactoring loops and accidentally stripping key safety filters.',
    advisory: {
      id: 'GHSA-2020-7754',
      title: 'Prototype Pollution in Object Deep Merge',
      description: 'Recursive clone failed to filter __proto__ properties allowing global prototype tampering.',
      cwe: 'CWE-1321',
      severity: 'HIGH',
      affectedPackage: 'deep-merge-json',
      affectedVersions: '< 3.1.0',
      patchedVersions: '>= 3.1.0',
      fixCommitSha: '8d2e4f0',
      patchDiff: `@@ -5,2 +5,3 @@
+if (key === '__proto__' || key === 'constructor') continue;
 target[key] = source[key];`,
      discoveredAt: '2020-09-01',
    },
    invariant: {
      id: 'INV-GHSA-2020-7754-01',
      advisoryId: 'GHSA-2020-7754',
      packageName: 'deep-merge-json',
      createdAt: '2020-09-02T10:00:00Z',
      type: 'GUARD_REMOVAL',
      params: {
        source: 'source[key]',
        sink: 'target',
        guard: '__proto__',
      },
      vulnerabilityType: 'CWE-1321',
      fixCommitSha: '8d2e4f0',
      rationale: 'Prevent prototype pollution by filtering prototype property names',
      enabled: true,
    },
    vulnerableCode: `function merge(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
  return target;
}`,
    fixedCode: `function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor') {
      continue;
    }
    target[key] = source[key];
  }
  return target;
}`,
    prDiff: `@@ -3,3 +3,1 @@
-    if (key === '__proto__' || key === 'constructor') {
-      continue;
-    }
+    // Cleaned up merge loop`,
    prCode: `function merge(target, source) {
  for (const key of Object.keys(source)) {
    // Cleaned up merge loop
    target[key] = source[key];
  }
  return target;
}`,
    expectedVerdict: 'PROVEN',
  },

  {
    id: 'cve-2022-merge-conflict-revert',
    name: 'Merge Conflict Accidental Revert (Inverse Patch)',
    category: 'Regression Revert',
    cwe: 'CWE-1188',
    description: 'During a messy git rebase or merge conflict, the developer chose "accept incoming" which reverted a security fix.',
    whyItMatters: 'Demonstrates Inverse-Patch detection flagging a silent revert of a 2-year-old security fix.',
    advisory: {
      id: 'GHSA-2022-31129',
      title: 'Timing Attack Protection Revert',
      description: 'Constant-time comparison guard was accidentally reverted during git merge.',
      cwe: 'CWE-208',
      severity: 'HIGH',
      affectedPackage: 'auth-tokens',
      affectedVersions: '< 4.0.0',
      patchedVersions: '>= 4.0.0',
      fixCommitSha: '3b9f2c1',
      patchDiff: `@@ -3,2 +3,2 @@
-if (token === expectedToken) return true;
+if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) return true;`,
      discoveredAt: '2022-11-04',
    },
    invariant: {
      id: 'INV-GHSA-2022-31129-01',
      advisoryId: 'GHSA-2022-31129',
      packageName: 'auth-tokens',
      createdAt: '2022-11-05T10:00:00Z',
      type: 'INVERSE_PATCH',
      params: {
        originalAddedLines: ['crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))'],
        originalRemovedLines: ['token === expectedToken'],
        similarityThreshold: 0.7,
      },
      vulnerabilityType: 'CWE-208',
      fixCommitSha: '3b9f2c1',
      rationale: 'Protect against timing side-channel attacks by enforcing constant-time comparisons',
      enabled: true,
    },
    vulnerableCode: `function verify(token, expectedToken) {
  if (token === expectedToken) return true;
  return false;
}`,
    fixedCode: `const crypto = require('crypto');
function verify(token, expectedToken) {
  if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) return true;
  return false;
}`,
    prDiff: `@@ -2,2 +2,2 @@
-  if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) return true;
+  if (token === expectedToken) return true;`,
    prCode: `function verify(token, expectedToken) {
  if (token === expectedToken) return true;
  return false;
}`,
    expectedVerdict: 'PROVEN',
  },

  {
    id: 'benign-refactor-rename',
    name: 'Benign Refactor: Code Cleanup & Renaming',
    category: 'Benign Control',
    cwe: 'None',
    description: 'Maintainer cleans up variables, adds comments and logs without compromising security checks.',
    whyItMatters: 'Proves PATCHBACK has 0% false positives on legitimate refactors.',
    advisory: {
      id: 'GHSA-2022-29244',
      title: 'Path Traversal Arbitrary File Read in Static Server',
      description: 'Lack of root boundary validation allowed attackers to escape root via ../ sequences.',
      cwe: 'CWE-22',
      severity: 'HIGH',
      affectedPackage: 'serve-static-core',
      affectedVersions: '< 2.0.0',
      patchedVersions: '>= 2.0.0',
      fixCommitSha: '7a9c8f1',
      patchDiff: `+if (!p.startsWith(root)) return r.status(403);`,
      discoveredAt: '2022-06-15',
    },
    invariant: {
      id: 'INV-GHSA-2022-29244-01',
      advisoryId: 'GHSA-2022-29244',
      packageName: 'serve-static-core',
      createdAt: '2022-06-16T10:00:00Z',
      type: 'GUARD_DOMINATES',
      params: {
        source: 'req.query.p',
        sink: 'res.sendFile',
        guard: 'startsWith(root)',
      },
      vulnerabilityType: 'CWE-22',
      fixCommitSha: '7a9c8f1',
      rationale: 'Guard required to stop directory traversal escaping root directory',
      enabled: true,
    },
    vulnerableCode: `app.get('/f', (q, r) => { r.sendFile(path.join(root, q.query.p)); });`,
    fixedCode: `app.get('/f', (q, r) => {
  const p = path.resolve(root, q.query.p);
  if (!p.startsWith(root)) return r.status(403);
  r.sendFile(p);
});`,
    prDiff: `@@ -1,5 +1,8 @@
+// Cleaned up parameters and added descriptive logging
+app.get('/f', (req, res) => {
+  console.log('Serving requested asset');
+  const targetPath = path.resolve(root, req.query.p);
+  if (!targetPath.startsWith(root)) return res.status(403);
+  res.sendFile(targetPath);
+});`,
    prCode: `const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

// Cleaned up parameters and added descriptive logging
app.get('/f', (req, res) => {
  console.log('Serving requested asset');
  const targetPath = path.resolve(root, req.query.p);
  if (!targetPath.startsWith(root)) return res.status(403);
  res.sendFile(targetPath);
});`,
    expectedVerdict: 'BENIGN',
  },

  {
    id: 'benign-route-addition',
    name: 'Benign Addition: New Unrelated Endpoint',
    category: 'Benign Control',
    cwe: 'None',
    description: 'Adding a health check or status endpoint that does not interact with protected sinks.',
    whyItMatters: 'Confirms that adding new routes does not generate false alarms.',
    advisory: {
      id: 'GHSA-2022-29244',
      title: 'Path Traversal Arbitrary File Read in Static Server',
      description: 'Lack of root boundary validation allowed attackers to escape root via ../ sequences.',
      cwe: 'CWE-22',
      severity: 'HIGH',
      affectedPackage: 'serve-static-core',
      affectedVersions: '< 2.0.0',
      patchedVersions: '>= 2.0.0',
      fixCommitSha: '7a9c8f1',
      patchDiff: `+if (!p.startsWith(root)) return r.status(403);`,
      discoveredAt: '2022-06-15',
    },
    invariant: {
      id: 'INV-GHSA-2022-29244-01',
      advisoryId: 'GHSA-2022-29244',
      packageName: 'serve-static-core',
      createdAt: '2022-06-16T10:00:00Z',
      type: 'GUARD_DOMINATES',
      params: {
        source: 'q.query.p',
        sink: 'r.sendFile',
        guard: 'startsWith(root)',
      },
      vulnerabilityType: 'CWE-22',
      fixCommitSha: '7a9c8f1',
      rationale: 'Guard required to stop directory traversal escaping root directory',
      enabled: true,
    },
    vulnerableCode: `app.get('/f', (q, r) => { r.sendFile(path.join(root, q.query.p)); });`,
    fixedCode: `app.get('/f', (q, r) => {
  const p = path.resolve(root, q.query.p);
  if (!p.startsWith(root)) return r.status(403);
  r.sendFile(p);
});`,
    prDiff: `@@ -10,3 +10,6 @@
+app.get('/health', (req, res) => {
+  res.json({ status: 'ok', uptime: process.uptime() });
+});`,
    prCode: `const express = require('express');
const path = require('path');
const app = express();
const root = '/var/www/static';

app.get('/f', (q, r) => {
  const p = path.resolve(root, q.query.p);
  if (!p.startsWith(root)) return r.status(403);
  r.sendFile(p);
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});`,
    expectedVerdict: 'BENIGN',
  },
];
