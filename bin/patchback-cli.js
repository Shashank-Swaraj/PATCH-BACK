#!/usr/bin/env node

/**
 * PATCHBACK Local CLI Scanner
 * Allows developers and CI workflows to scan local files or PR diffs
 * for security regressions before merging.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { checkSecurityInvariant } from '../engine/checker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
PATCHBACK - Security Regression Intelligence CLI
"Remember the fix. Protect the future."

Usage:
  node bin/patchback-cli.js [options]

Options:
  --file <path>       Path to local JavaScript file to scan
  --sink <pattern>    Dangerous sink to detect (e.g. "res.sendFile", "exec", "target[key]")
  --guard <pattern>   Required defensive guard (e.g. "startsWith", "shellEscape", "__proto__")
  --scenario <id>     Run one of the built-in scenarios (1-6)
  --benchmark         Run the full 6-scenario benchmark scorecard
  --help              Display this help menu

Examples:
  node bin/patchback-cli.js --file ./server.js --sink res.sendFile --guard startsWith
  node bin/patchback-cli.js --scenario 1
  node bin/patchback-cli.js --benchmark
`);
}

async function run() {
  if (args.includes('--help') || args.length === 0) {
    printHelp();
    return;
  }

  if (args.includes('--benchmark')) {
    const { execSync } = await import('child_process');
    execSync('node pitch-and-benchmark/benchmark-runner.js', { stdio: 'inherit' });
    return;
  }

  const scenarioIndex = args.indexOf('--scenario');
  if (scenarioIndex !== -1) {
    const id = args[scenarioIndex + 1];
    const scenarioMap = {
      '1': '01-path-traversal.js',
      '2': '02-command-injection.js',
      '3': '03-benign-clean-pr.js',
      '4': '04-prototype-pollution.js',
      '5': '05-timing-attack.js',
      '6': '06-benign-route-addition.js',
    };
    const file = scenarioMap[id] || `${id}.js`;
    const fullPath = path.resolve(__dirname, '../scenarios', file);
    if (!fs.existsSync(fullPath)) {
      console.error(`Error: Scenario "${id}" not found.`);
      process.exit(1);
    }
    const { scenario } = await import(`file://${fullPath.replace(/\\/g, '/')}`);
    console.log(`\n🔍 Scanning Scenario: ${scenario.name} (${scenario.cwe || 'OWASP'})\n`);
    const analysis = checkSecurityInvariant(scenario.prCode, scenario.sink, scenario.guard);
    printResult(scenario.name, scenario.sink, scenario.guard, analysis);
    return;
  }

  const fileIndex = args.indexOf('--file');
  const sinkIndex = args.indexOf('--sink');
  const guardIndex = args.indexOf('--guard');

  if (fileIndex === -1 || sinkIndex === -1 || guardIndex === -1) {
    console.error('Error: Please provide --file, --sink, and --guard');
    printHelp();
    process.exit(1);
  }

  const filePath = path.resolve(process.cwd(), args[fileIndex + 1]);
  const sink = args[sinkIndex + 1];
  const guard = args[guardIndex + 1];

  if (!fs.existsSync(filePath)) {
    console.error(`Error: Target file not found: ${filePath}`);
    process.exit(1);
  }

  const code = fs.readFileSync(filePath, 'utf8');
  console.log(`\n🔍 PATCHBACK Invariant Scan on: ${filePath}`);
  console.log(`🎯 Target Sink:  ${sink}`);
  console.log(`🛡️  Required Guard: ${guard}\n`);

  const analysis = checkSecurityInvariant(code, sink, guard);
  printResult(path.basename(filePath), sink, guard, analysis);
}

function printResult(target, sink, guard, analysis) {
  console.log('-------------------------------------------------------------');
  if (analysis.verdict === 'SAFE_PASS') {
    console.log('✅ VERDICT: SAFE TO MERGE (SAFE_PASS)');
    console.log(`⚡ Verified in ${analysis.latencyMs} ms | Zero Invariant Violations`);
    console.log('-------------------------------------------------------------\n');
    process.exit(0);
  } else {
    console.log('❌ VERDICT: REGRESSION DETECTED (PROVEN_REGRESSION)');
    console.log(`⚡ Verified in ${analysis.latencyMs} ms`);
    console.log(`🚨 Violations Found (${analysis.violations.length}):`);
    analysis.violations.forEach((v, idx) => {
      console.log(`   ${idx + 1}. Line ${v.line}: ${v.reason || 'Missing required defensive guard'}`);
    });
    console.log('\n[PATCHBACK CI Bot Comment Preview]:');
    console.log(`> ❌ **PATCHBACK Gate Failed for ${target}**`);
    console.log(`> A historical security check (\`${guard}\`) protecting \`${sink}\` was bypassed.`);
    console.log('> Pull request merge blocked to protect repository security.');
    console.log('-------------------------------------------------------------\n');
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('Execution error:', err.message);
  process.exit(1);
});
