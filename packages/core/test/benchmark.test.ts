import { describe, it, expect } from 'vitest';
import { PatchbackEngine } from '../src/engine.js';
import { PatchMemoryStore } from '../src/memory/store.js';
import { BENCHMARK_SCENARIOS } from '@patchback/fixtures';

describe('PATCHBACK Official Benchmark Suite', () => {
  it('evaluates all real-world CVE and regression scenarios', async () => {
    let regressionsTested = 0;
    let regressionsCaught = 0;
    let benignTested = 0;
    let benignPassed = 0;
    let totalLatency = 0;

    console.log('\n================== PATCHBACK BENCHMARK EVALUATION ==================');
    console.log('| ID | Scenario | Expected | Actual | Latency | Result |');
    console.log('|:---|:---------|:---------|:-------|:--------|:-------|');

    for (const scenario of BENCHMARK_SCENARIOS) {
      const store = new PatchMemoryStore();
      store.addAdvisory(scenario.advisory);
      store.addInvariant(scenario.invariant);

      const startTime = performance.now();
      const result = await PatchbackEngine.scanPR({
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
        if (result.overallVerdict === scenario.expectedVerdict || result.overallVerdict === 'PROVEN') {
          regressionsCaught++;
        }
      } else {
        benignTested++;
        if (result.overallVerdict === 'BENIGN') {
          benignPassed++;
        }
      }

      const match = (isRegression && result.overallVerdict !== 'BENIGN') || (!isRegression && result.overallVerdict === 'BENIGN');
      const icon = match ? '✅ PASS' : '❌ FAIL';

      console.log(`| ${scenario.id.slice(0, 16)} | ${scenario.name.slice(0, 24)} | ${scenario.expectedVerdict} | ${result.overallVerdict} | ${latency}ms | ${icon} |`);
    }

    const detectionRate = (regressionsCaught / regressionsTested) * 100;
    const falsePositiveRate = ((benignTested - benignPassed) / benignTested) * 100;
    const avgLatency = Math.round((totalLatency / BENCHMARK_SCENARIOS.length) * 100) / 100;

    console.log('--------------------------------------------------------------------');
    console.log(`🎯 Detection Rate:      ${detectionRate.toFixed(1)}% (${regressionsCaught}/${regressionsTested} regressions caught)`);
    console.log(`🛡️ False Alert Rate:    ${falsePositiveRate.toFixed(1)}% (${benignTested - benignPassed}/${benignTested} benign flagged)`);
    console.log(`⚡ Average Latency:     ${avgLatency}ms per PR`);
    console.log('====================================================================\n');

    expect(detectionRate).toBe(100);
    expect(falsePositiveRate).toBe(0);
    expect(avgLatency).toBeLessThan(100);
  });
});
