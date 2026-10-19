#!/usr/bin/env node
import { Command } from 'commander';
import { BENCHMARK_SCENARIOS } from '@patchback/fixtures';
import { PatchbackEngine, PatchMemoryStore, formatGitHubPRComment } from '@patchback/core';
import fs from 'node:fs';

const program = new Command();

program
  .name('patchback')
  .description('PATCHBACK: Security Regression Intelligence for Open-Source Packages')
  .version('0.1.0');

program
  .command('benchmark')
  .description('Run the official security regression benchmark suite')
  .action(async () => {
    console.log('\n================== PATCHBACK BENCHMARK EVALUATION ==================');
    console.log('| ID | Scenario | Expected | Actual | Latency | Result |');
    console.log('|:---|:---------|:---------|:-------|:--------|:-------|');

    let regressionsTested = 0;
    let regressionsCaught = 0;
    let benignTested = 0;
    let benignPassed = 0;
    let totalLatency = 0;

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

      const match =
        (isRegression && result.overallVerdict !== 'BENIGN') ||
        (!isRegression && result.overallVerdict === 'BENIGN');
      const icon = match ? '✅ PASS' : '❌ FAIL';

      console.log(
        `| ${scenario.id.slice(0, 16)} | ${scenario.name.slice(0, 24)} | ${scenario.expectedVerdict} | ${result.overallVerdict} | ${latency}ms | ${icon} |`
      );
    }

    const detectionRate = (regressionsCaught / regressionsTested) * 100;
    const falsePositiveRate = ((benignTested - benignPassed) / benignTested) * 100;
    const avgLatency = Math.round((totalLatency / BENCHMARK_SCENARIOS.length) * 100) / 100;

    console.log('--------------------------------------------------------------------');
    console.log(`🎯 Detection Rate:      ${detectionRate.toFixed(1)}% (${regressionsCaught}/${regressionsTested} regressions caught)`);
    console.log(`🛡️ False Alert Rate:    ${falsePositiveRate.toFixed(1)}% (${benignTested - benignPassed}/${benignTested} benign flagged)`);
    console.log(`⚡ Average Latency:     ${avgLatency}ms per PR`);
    console.log('====================================================================\n');
  });

program
  .command('demo')
  .description('Run interactive simulation of the pitch deck Express path traversal scenario')
  .action(async () => {
    const scenario = BENCHMARK_SCENARIOS[0];
    console.log('\n--- ACT 1: Historical Fix (2022) ---');
    console.log(`Advisory: ${scenario.advisory.id} - ${scenario.advisory.title}`);
    console.log(`Security Invariant: ${scenario.invariant.type} (${scenario.invariant.id})`);
    console.log(`Rule: Sink '${(scenario.invariant.params as any).sink}' MUST be dominated by guard '${(scenario.invariant.params as any).guard}'`);

    console.log('\n--- ACT 2: Refactoring Pull Request (2024) ---');
    console.log('PR #412 "Extract helper function sendAsset" opened.');
    console.log('CodeQL / Dependabot: Passed (No known vulnerable version change, no AST query match)');

    console.log('\n--- ACT 3: PATCHBACK Deterministic Evaluation ---');
    const store = new PatchMemoryStore();
    store.addAdvisory(scenario.advisory);
    store.addInvariant(scenario.invariant);

    const result = await PatchbackEngine.scanPR({
      packageName: scenario.invariant.packageName,
      targets: [
        {
          filePath: 'routes.js',
          currentContent: scenario.prCode,
          diff: scenario.prDiff,
        },
      ],
      prNumber: 412,
      memoryStore: store,
    });

    console.log(`Scan completed in ${result.durationMs}ms`);
    console.log(`Verdict: ${result.overallVerdict} REGRESSION\n`);

    const comment = formatGitHubPRComment(result, {
      [scenario.advisory.id]: scenario.advisory,
    });

    console.log('Simulated GitHub PR Comment:\n');
    console.log(comment);
  });

program.parse(process.argv);
