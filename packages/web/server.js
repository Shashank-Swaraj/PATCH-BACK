import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PatchbackEngine,
  PatchMemoryStore,
  runSanityGate,
  formatGitHubPRComment,
} from '@patchback/core';
import { BENCHMARK_SCENARIOS } from '@patchback/fixtures';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Initialize global Patch Memory with benchmark advisories & invariants
const memoryStore = new PatchMemoryStore();
for (const s of BENCHMARK_SCENARIOS) {
  memoryStore.addAdvisory(s.advisory);
  memoryStore.addInvariant(s.invariant);
}

// 1. Get all scenarios
app.get('/api/scenarios', (req, res) => {
  res.json({ scenarios: BENCHMARK_SCENARIOS });
});

// 2. Run Sanity Gate validation
app.post('/api/sanity-gate', (req, res) => {
  try {
    const { invariant, vulnerableCode, fixedCode } = req.body;
    const gateResult = runSanityGate(invariant, vulnerableCode, fixedCode);
    res.json({ result: gateResult });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// 3. Scan a PR
app.post('/api/scan', async (req, res) => {
  try {
    const { packageName, prCode, prDiff, invariant, advisory, prNumber = 412 } = req.body;

    const sessionStore = new PatchMemoryStore();
    if (advisory) sessionStore.addAdvisory(advisory);
    if (invariant) sessionStore.addInvariant(invariant);

    // Also include tracked invariants from main store
    for (const inv of memoryStore.getInvariantsForPackage(packageName)) {
      if (!sessionStore.getInvariant(inv.id)) {
        sessionStore.addInvariant(inv);
      }
    }

    const result = await PatchbackEngine.scanPR({
      packageName,
      targets: [
        {
          filePath: 'routes.js',
          currentContent: prCode,
          diff: prDiff,
        },
      ],
      prNumber,
      memoryStore: sessionStore,
    });

    const advisoriesMap = {};
    if (advisory) advisoriesMap[advisory.id] = advisory;
    for (const adv of memoryStore.getAllAdvisories()) {
      advisoriesMap[adv.id] = adv;
    }

    const prComment = formatGitHubPRComment(result, advisoriesMap);

    res.json({
      result,
      prComment,
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// 4. Run full benchmark suite
app.get('/api/benchmark', async (req, res) => {
  try {
    let regressionsTested = 0;
    let regressionsCaught = 0;
    let benignTested = 0;
    let benignPassed = 0;
    let totalLatency = 0;
    const results = [];

    for (const scenario of BENCHMARK_SCENARIOS) {
      const store = new PatchMemoryStore();
      store.addAdvisory(scenario.advisory);
      store.addInvariant(scenario.invariant);

      const startTime = performance.now();
      const scanResult = await PatchbackEngine.scanPR({
        packageName: scenario.invariant.packageName,
        targets: [
          {
            filePath: 'index.js',
            currentContent: scenario.prCode,
            diff: scenario.prDiff,
          },
        ],
        memoryStore: store,
      });
      const latency = Math.round((performance.now() - startTime) * 100) / 100;
      totalLatency += latency;

      const isRegression = scenario.expectedVerdict !== 'BENIGN';
      if (isRegression) {
        regressionsTested++;
        if (scanResult.overallVerdict === scenario.expectedVerdict || scanResult.overallVerdict === 'PROVEN') {
          regressionsCaught++;
        }
      } else {
        benignTested++;
        if (scanResult.overallVerdict === 'BENIGN') {
          benignPassed++;
        }
      }

      const match =
        (isRegression && scanResult.overallVerdict !== 'BENIGN') ||
        (!isRegression && scanResult.overallVerdict === 'BENIGN');

      results.push({
        id: scenario.id,
        name: scenario.name,
        category: scenario.category,
        expected: scenario.expectedVerdict,
        actual: scanResult.overallVerdict,
        latency,
        match,
        violationsCount: scanResult.violations.length,
      });
    }

    const detectionRate = (regressionsCaught / regressionsTested) * 100;
    const falseAlertRate = ((benignTested - benignPassed) / benignTested) * 100;
    const avgLatency = Math.round((totalLatency / BENCHMARK_SCENARIOS.length) * 100) / 100;

    res.json({
      detectionRate,
      falseAlertRate,
      avgLatency,
      regressionsCaught,
      regressionsTested,
      benignPassed,
      benignTested,
      results,
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// 5. Get memory store
app.get('/api/invariants', (req, res) => {
  res.json({
    invariants: memoryStore.getAllInvariants(),
    advisories: memoryStore.getAllAdvisories(),
  });
});

// Serve frontend build if dist/client exists
const clientDist = path.join(__dirname, 'dist/client');
app.use(express.static(clientDist));
app.get('*', (req, res) => {
  res.sendFile(path.join(clientDist, 'index.html'), (err) => {
    if (err) {
      res.json({ status: 'PATCHBACK Backend Running on port ' + PORT, apiEndpoints: ['/api/scenarios', '/api/scan', '/api/benchmark', '/api/invariants'] });
    }
  });
});

app.listen(PORT, () => {
  console.log(`🚀 PATCHBACK Server running on http://localhost:${PORT}`);
});
