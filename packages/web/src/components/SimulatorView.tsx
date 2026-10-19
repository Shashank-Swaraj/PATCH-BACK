import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Play,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  GitPullRequest,
  History,
  Copy,
  Check,
  Zap,
} from 'lucide-react';

interface Scenario {
  id: string;
  name: string;
  category: string;
  cwe: string;
  description: string;
  whyItMatters: string;
  advisory: any;
  invariant: any;
  vulnerableCode: string;
  fixedCode: string;
  prDiff: string;
  prCode: string;
  expectedVerdict: string;
}

export const SimulatorView: React.FC = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);
  const [sanityGateResult, setSanityGateResult] = useState<any>(null);
  const [isEvaluatingGate, setIsEvaluatingGate] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [prComment, setPrComment] = useState<string>('');
  const [isScanning, setIsScanning] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch('/api/scenarios')
      .then((res) => res.json())
      .then((data) => {
        if (data.scenarios && data.scenarios.length > 0) {
          setScenarios(data.scenarios);
          setSelectedScenario(data.scenarios[0]);
        }
      })
      .catch((err) => console.error('Failed to load scenarios:', err));
  }, []);

  useEffect(() => {
    // Reset test state when changing scenario
    setSanityGateResult(null);
    setScanResult(null);
    setPrComment('');
  }, [selectedScenario]);

  const handleRunSanityGate = async () => {
    if (!selectedScenario) return;
    setIsEvaluatingGate(true);
    try {
      const res = await fetch('/api/sanity-gate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invariant: selectedScenario.invariant,
          vulnerableCode: selectedScenario.vulnerableCode,
          fixedCode: selectedScenario.fixedCode,
        }),
      });
      const data = await res.json();
      setSanityGateResult(data.result);
    } catch (err) {
      console.error('Sanity gate error:', err);
    } finally {
      setIsEvaluatingGate(false);
    }
  };

  const handleRunScan = async () => {
    if (!selectedScenario) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          packageName: selectedScenario.invariant.packageName,
          prCode: selectedScenario.prCode,
          prDiff: selectedScenario.prDiff,
          invariant: selectedScenario.invariant,
          advisory: selectedScenario.advisory,
          prNumber: 412,
        }),
      });
      const data = await res.json();
      setScanResult(data.result);
      setPrComment(data.prComment);
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const copyComment = () => {
    if (!prComment) return;
    navigator.clipboard.writeText(prComment);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!selectedScenario) {
    return (
      <div className="py-20 text-center text-slate-400">
        <Zap className="w-8 h-8 mx-auto mb-2 animate-bounce text-cyan-400" />
        Loading PATCHBACK Simulation Engine...
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
      {/* Top Selector Bar */}
      <div className="glass-panel p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
              Simulation Scenario
            </span>
            <h2 className="text-xl font-bold text-white mt-0.5">
              {selectedScenario.name}
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              {selectedScenario.whyItMatters}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedScenario.id}
              onChange={(e) => {
                const found = scenarios.find((s) => s.id === e.target.value);
                if (found) setSelectedScenario(found);
              }}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-sm rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-medium"
            >
              {scenarios.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.expectedVerdict === 'BENIGN' ? '🟢' : '🚨'} {s.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Grid: Act 1 & Act 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* ACT 1: Historical Fix */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-blue-400" />
                <h3 className="font-semibold text-white">Act 1: Historical Security Fix (2022)</h3>
              </div>
              <span className="text-xs px-2.5 py-1 rounded-full bg-blue-950/80 text-blue-400 border border-blue-800/60 font-mono">
                {selectedScenario.advisory.id}
              </span>
            </div>

            <div className="p-3.5 bg-slate-900/80 rounded-lg border border-slate-800 text-sm space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Vulnerability:</span>
                <span className="text-rose-400 font-semibold">{selectedScenario.cwe}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Severity:</span>
                <span className="text-amber-400 font-semibold">{selectedScenario.advisory.severity}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Fix Commit:</span>
                <span className="text-cyan-400 font-mono">{selectedScenario.advisory.fixCommitSha}</span>
              </div>
              <p className="text-xs text-slate-300 pt-1 border-t border-slate-800">
                {selectedScenario.advisory.description}
              </p>
            </div>

            {/* Invariant Rule Card */}
            <div className="p-3.5 bg-cyan-950/20 border border-cyan-800/40 rounded-lg">
              <span className="text-xs font-semibold text-cyan-400 block mb-1">
                Typed Security Invariant (Patch Memory):
              </span>
              <code className="text-xs font-mono text-cyan-200 block break-all">
                {selectedScenario.invariant.type}(
                {selectedScenario.invariant.type === 'GUARD_DOMINATES' &&
                  `sink=${selectedScenario.invariant.params.sink}, guard=${selectedScenario.invariant.params.guard}`}
                {selectedScenario.invariant.type === 'SANITIZER_SWAP' &&
                  `sink=${selectedScenario.invariant.params.sink}, sanitizer=${selectedScenario.invariant.params.requiredSanitizer}`}
                {selectedScenario.invariant.type === 'GUARD_REMOVAL' &&
                  `guard=${selectedScenario.invariant.params.guard}`}
                {selectedScenario.invariant.type === 'INVERSE_PATCH' &&
                  `threshold=${selectedScenario.invariant.params.similarityThreshold}`}
                )
              </code>
            </div>

            {/* Sanity Gate Status */}
            {sanityGateResult && (
              <div
                className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2.5 ${
                  sanityGateResult.passed
                    ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-800 text-rose-300'
                }`}
              >
                {sanityGateResult.passed ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                )}
                <div>
                  <div className="font-bold">
                    {sanityGateResult.passed
                      ? 'Sanity Gate PASSED: Invariant Validated'
                      : 'Sanity Gate REJECTED Invariant'}
                  </div>
                  <div>• Failed on unpatched code: {sanityGateResult.failedOnVulnerable ? 'Yes (Detected flaw)' : 'No'}</div>
                  <div>• Holds on patched code: {sanityGateResult.holdsOnFixed ? 'Yes (Safely guarded)' : 'No'}</div>
                  <div className="text-[11px] text-slate-400 mt-1">Rule accepted into Patch Memory database.</div>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={handleRunSanityGate}
            disabled={isEvaluatingGate}
            className="btn-secondary w-full justify-center mt-5"
          >
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            {isEvaluatingGate ? 'Validating on AST...' : 'Run Machine Sanity Gate Test'}
          </button>
        </div>

        {/* ACT 2: The Refactoring PR */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <GitPullRequest className="w-5 h-5 text-purple-400" />
                <h3 className="font-semibold text-white">Act 2: Incoming Pull Request (2024)</h3>
              </div>
              <span className="text-xs px-2.5 py-1 rounded-full bg-purple-950/80 text-purple-400 border border-purple-800/60 font-mono">
                PR #412
              </span>
            </div>

            {/* The Blindness Callout */}
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-400 font-medium">Dependabot</div>
                <div className="text-slate-500 font-semibold mt-0.5">🙈 Blind</div>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-400 font-medium">CodeQL / SAST</div>
                <div className="text-slate-500 font-semibold mt-0.5">⚠️ No Rule</div>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-400 font-medium">Human Review</div>
                <div className="text-amber-400 font-semibold mt-0.5">👀 Misses Why</div>
              </div>
            </div>

            {/* PR Diff Viewer */}
            <div className="rounded-lg overflow-hidden border border-slate-800 bg-slate-950 text-xs font-mono">
              <div className="bg-slate-900 px-3 py-1.5 text-slate-400 border-b border-slate-800 flex items-center justify-between">
                <span>diff --git a/routes.js b/routes.js</span>
                <span className="text-emerald-400">+Added / -Removed</span>
              </div>
              <pre className="p-3 overflow-x-auto text-slate-300 max-h-56">
                {selectedScenario.prDiff.split('\n').map((line, idx) => {
                  let color = 'text-slate-400';
                  let bg = '';
                  if (line.startsWith('+') && !line.startsWith('+++')) {
                    color = 'text-emerald-300';
                    bg = 'bg-emerald-950/30';
                  } else if (line.startsWith('-') && !line.startsWith('---')) {
                    color = 'text-rose-300';
                    bg = 'bg-rose-950/30';
                  }
                  return (
                    <div key={idx} className={`${color} ${bg} px-1 rounded`}>
                      {line}
                    </div>
                  );
                })}
              </pre>
            </div>
          </div>

          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="btn-primary w-full justify-center mt-5"
          >
            <Play className="w-4 h-4 fill-white" />
            {isScanning ? 'Running AST Invariant Evaluation...' : 'Run PATCHBACK Invariant Check'}
          </button>
        </div>
      </div>

      {/* ACT 3: The Verdict & Evidence */}
      {scanResult && (
        <div
          className={`glass-panel p-6 border-2 transition-all duration-300 ${
            scanResult.overallVerdict === 'BENIGN'
              ? 'glass-panel-success'
              : 'glass-panel-danger'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div className="flex items-center gap-3">
              {scanResult.overallVerdict === 'BENIGN' ? (
                <div className="w-12 h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center border border-emerald-500/40">
                  <CheckCircle2 className="w-7 h-7 text-emerald-400" />
                </div>
              ) : (
                <div className="w-12 h-12 rounded-xl bg-rose-500/20 flex items-center justify-center border border-rose-500/40">
                  <AlertTriangle className="w-7 h-7 text-rose-400" />
                </div>
              )}
              <div>
                <div className="flex items-center gap-3">
                  <h3 className="text-xl font-bold text-white">
                    {scanResult.overallVerdict === 'BENIGN'
                      ? 'No Regression Detected'
                      : 'Security Regression Detected!'}
                  </h3>
                  <span
                    className={
                      scanResult.overallVerdict === 'BENIGN'
                        ? 'badge-benign'
                        : 'badge-proven'
                    }
                  >
                    {scanResult.overallVerdict} REGRESSION
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Evaluated {scanResult.totalInvariantsChecked} invariants in{' '}
                  <span className="text-cyan-400 font-mono font-bold">
                    {scanResult.durationMs}ms
                  </span>{' '}
                  (Deterministic static analysis, 0 LLM hallucinations)
                </p>
              </div>
            </div>

            <button onClick={copyComment} className="btn-secondary text-xs">
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied PR Comment!' : 'Copy PR Comment Markdown'}
            </button>
          </div>

          {/* Evidence Path Callout */}
          {scanResult.violations.length > 0 && (
            <div className="mt-6 space-y-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-rose-400">
                <Terminal className="w-4 h-4" />
                <span>Deterministic Execution Traceback:</span>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
                {scanResult.violations[0].evidencePath.map((step: any, idx: number) => (
                  <div key={idx} className="flex items-start gap-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        step.role === 'SINK'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : step.role === 'SOURCE'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : step.role === 'MISSING_GUARD'
                          ? 'bg-purple-950 text-purple-300 border border-purple-800'
                          : 'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}
                    >
                      {step.role}
                    </span>
                    <div className="flex-1">
                      <span className="text-slate-400">{step.file}:{step.line}</span>
                      <div className="text-slate-200 mt-0.5 bg-slate-900/60 p-1.5 rounded">
                        {step.codeSnippet}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Remediation Note */}
              <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
                <span className="text-cyan-400 font-semibold">Remediation: </span>
                {scanResult.violations[0].remediation}
              </div>
            </div>
          )}

          {/* GitHub PR Comment Simulation Box */}
          <div className="mt-6">
            <span className="text-xs font-semibold text-slate-400 block mb-2">
              GitHub Action Output Preview:
            </span>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-64 overflow-y-auto">
              {prComment}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
