import { describe, it, expect } from 'vitest';
import { PatchbackEngine } from '../src/engine.js';
import { PatchMemoryStore } from '../src/memory/store.js';
import { SecurityInvariant } from '../src/types/invariant.js';
import { formatGitHubPRComment } from '../src/reporter/markdown.js';

describe('Patchback Engine PR Evaluation', () => {
  const store = new PatchMemoryStore();

  const invariant: SecurityInvariant = {
    id: 'INV-PATH-001',
    advisoryId: 'GHSA-2022-FILE-PASS',
    packageName: 'express-file-app',
    createdAt: new Date().toISOString(),
    type: 'GUARD_DOMINATES',
    params: {
      source: 'q.query.p',
      sink: 'r.sendFile',
      guard: 'startsWith(root)',
    },
    vulnerabilityType: 'CWE-22: Path Traversal',
    fixCommitSha: 'fixcommit123',
    rationale: 'Guard required to stop directory traversal',
    enabled: true,
  };

  store.addInvariant(invariant);
  store.addAdvisory({
    id: 'GHSA-2022-FILE-PASS',
    title: 'Arbitrary File Read via Path Traversal',
    description: 'Path traversal flaw allowed remote attackers to read server files via query parameter.',
    cwe: 'CWE-22',
    severity: 'HIGH',
    affectedPackage: 'express-file-app',
    affectedVersions: '< 1.2.0',
    patchedVersions: '>= 1.2.0',
    fixCommitSha: 'fixcommit123',
    patchDiff: '+ if (!p.startsWith(root)) return r.status(403);',
    discoveredAt: '2022-04-10',
  });

  it('detects guard bypass regression when helper function is extracted (Slide 4 scenario)', async () => {
    // PR #412 extracts helper function and adds a new route that calls sendAsset without the guard
    const prCode = `
      const express = require('express');
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

      app.get('/asset', (q, r) => {
        sendAsset(r, q.query.p);
      });
    `;

    const result = await PatchbackEngine.scanPR({
      packageName: 'express-file-app',
      targets: [
        {
          filePath: 'routes.js',
          currentContent: prCode,
        },
      ],
      prNumber: 412,
      commitSha: 'pr_commit_412',
      memoryStore: store,
    });

    expect(result.overallVerdict).toBe('PROVEN');
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].invariantId).toBe('INV-PATH-001');

    const comment = formatGitHubPRComment(result, {
      'GHSA-2022-FILE-PASS': store.getAdvisory('GHSA-2022-FILE-PASS')!,
    });

    expect(comment).toContain('PATCHBACK Security Regression Detected');
    expect(comment).toContain('PROVEN REGRESSION');
    expect(comment).toContain('GHSA-2022-FILE-PASS');
  });

  it('passes a benign refactor PR with 0 false positives', async () => {
    const benignPrCode = `
      const express = require('express');
      const path = require('path');
      const app = express();
      const root = '/var/www/static';

      // Benign cleanup: renamed variable and added logging
      app.get('/f', (req, res) => {
        console.log('Serving file request');
        const resolvedPath = path.resolve(root, req.query.p);
        if (!resolvedPath.startsWith(root)) {
          return res.status(403).send('Access denied');
        }
        res.sendFile(resolvedPath);
      });
    `;

    const result = await PatchbackEngine.scanPR({
      packageName: 'express-file-app',
      targets: [
        {
          filePath: 'routes.js',
          currentContent: benignPrCode,
        },
      ],
      prNumber: 413,
      commitSha: 'pr_commit_413',
      memoryStore: store,
    });

    expect(result.overallVerdict).toBe('BENIGN');
    expect(result.violations.length).toBe(0);
    expect(result.passedInvariantsCount).toBe(1);

    const comment = formatGitHubPRComment(result);
    expect(comment).toContain('All Security Invariants Preserved');
  });
});
