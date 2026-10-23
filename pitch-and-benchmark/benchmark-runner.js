
/**
 * Benchmark Scorecard Runner
 * Assigned to: Nikitah
 *
 * Loads scenarios, runs the security checker,
 * and compares actual verdicts with expected results.
 */

import { checkSecurityInvariant } from '../engine/checker.js';

import { scenario as pathTraversal } from '../scenarios/01-path-traversal.js';
import { scenario as commandInjection } from '../scenarios/02-command-injection.js';
import { scenario as benignCleanPR } from '../scenarios/03-benign-clean-pr.js';

const TEST_CASES = [
  pathTraversal,
  commandInjection,
  benignCleanPR,
];

console.log('\n--- PATCHBACK BENCHMARK SCORECARD ---\n');

const results = [];

for (const test of TEST_CASES) {
  let actual;
  let error = null;

  try {
    const analysis = checkSecurityInvariant(
      test.prCode,
      test.sink,
      test.guard
    );

    actual = analysis.verdict;
  } catch (err) {
    actual = 'ERROR';
    error = err.message;
  }

  const passed = actual === test.expectedResult;

  results.push({
    name: test.name,
    expected: test.expectedResult,
    actual,
    status: passed ? 'PASS' : 'FAIL',
    error,
  });
}

console.table(
  results.map(({ name, expected, actual, status }) => ({
    Scenario: name,
    Expected: expected,
    Actual: actual,
    Status: status,
  }))
);

const passedCount = results.filter(
  (result) => result.status === 'PASS'
).length;

console.log(`\nTotal scenarios: ${results.length}`);
console.log(`Passed: ${passedCount}`);
console.log(`Failed: ${results.length - passedCount}`);

for (const result of results) {
  if (result.error) {
    console.error(`\nError in "${result.name}": ${result.error}`);
  }
}

if (passedCount !== results.length) {
  process.exitCode = 1;
}
