import { describe, it, expect } from 'vitest';
import { runSanityGate } from '../src/sanity-gate/gate.js';
import { SecurityInvariant } from '../src/types/invariant.js';

describe('Sanity Gate Machine Validation', () => {
  const vulnerableApp = `
    const express = require('express');
    const path = require('path');
    const app = express();
    const root = '/var/www/static';

    app.get('/f', (q, r) => {
      const p = path.join(root, q.query.p);
      r.sendFile(p);
    });
  `;

  const patchedApp = `
    const express = require('express');
    const path = require('path');
    const app = express();
    const root = '/var/www/static';

    app.get('/f', (q, r) => {
      const p = path.resolve(root, q.query.p);
      if (!p.startsWith(root)) {
        return r.status(403).send('Forbidden');
      }
      r.sendFile(p);
    });
  `;

  it('validates a correct Guard-Dominates invariant (fails on vuln, passes on fix)', () => {
    const candidateInvariant: SecurityInvariant = {
      id: 'INV-CVE-2022-29244-01',
      advisoryId: 'GHSA-vulnerable-path-traversal',
      packageName: 'demo-file-server',
      createdAt: new Date().toISOString(),
      type: 'GUARD_DOMINATES',
      params: {
        source: 'q.query.p',
        sink: 'r.sendFile',
        guard: 'startsWith(root)',
      },
      vulnerabilityType: 'CWE-22: Path Traversal',
      fixCommitSha: 'a1b2c3d',
      rationale: 'Prevent arbitrary file read by enforcing root directory containment',
      enabled: true,
    };

    const result = runSanityGate(candidateInvariant, vulnerableApp, patchedApp);

    expect(result.failedOnVulnerable).toBe(true);
    expect(result.holdsOnFixed).toBe(true);
    expect(result.passed).toBe(true);
    expect(result.rejectionReason).toBeUndefined();
  });

  it('rejects an invalid invariant that does NOT trigger on vulnerable code', () => {
    const ineffectiveInvariant: SecurityInvariant = {
      id: 'INV-FAKE-01',
      advisoryId: 'GHSA-fake',
      packageName: 'demo-file-server',
      createdAt: new Date().toISOString(),
      type: 'GUARD_DOMINATES',
      params: {
        source: 'nonExistentSource',
        sink: 'nonExistentSink',
        guard: 'nonExistentGuard',
      },
      vulnerabilityType: 'CWE-22',
      fixCommitSha: 'a1b2c3d',
      rationale: 'Fake invariant',
      enabled: true,
    };

    const result = runSanityGate(ineffectiveInvariant, vulnerableApp, patchedApp);

    expect(result.failedOnVulnerable).toBe(false);
    expect(result.passed).toBe(false);
    expect(result.rejectionReason).toContain('Sanity gate failed: Invariant was NOT triggered on known vulnerable code');
  });
});
