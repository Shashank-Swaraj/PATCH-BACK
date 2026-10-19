import React from 'react';
import { Layers, Shield, Cpu, Terminal, GitCommit, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-10">
      {/* Hero Statement */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <span className="text-xs font-semibold text-cyan-400 uppercase tracking-widest">
          Core Engine Thesis
        </span>
        <h2 className="text-3xl font-extrabold text-white">
          "The LLM Proposes, Code Decides."
        </h2>
        <p className="text-sm text-slate-400">
          PATCHBACK decouples AI synthesis from CI enforcement. Invariants are drafted with AI assistance, machine-validated through a strict Sanity Gate, and enforced 100% deterministically using AST and Control Flow reachability.
        </p>
      </div>

      {/* 2-Phase Workflow Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Phase 1 */}
        <div className="glass-panel p-6 border-t-4 border-t-cyan-500 space-y-4">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <h3 className="font-bold text-white text-lg">Phase 1: Learn Once Per Fix</h3>
          </div>
          <p className="text-xs text-slate-400">
            Triggered once when a security vulnerability is patched (GHSA / OSV advisory).
          </p>

          <ol className="space-y-3 text-xs text-slate-300">
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-cyan-300 block">1. Advisory & Patch Ingestion</span>
              Parses the security record and the unified diff of the fix commit.
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-cyan-300 block">2. Invariant Classification</span>
              Classifies patch into one of 4 typed invariant templates (e.g. Guard Dominance).
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-cyan-300 block">3. Machine Sanity Gate</span>
              Must fail on unpatched code and pass on patched code before being accepted into memory.
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-cyan-300 block">4. Patch Memory Store</span>
              Stored with CVE ID, Commit SHA, and rationale in SQLite / JSON storage.
            </li>
          </ol>
        </div>

        {/* Phase 2 */}
        <div className="glass-panel p-6 border-t-4 border-t-emerald-500 space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h3 className="font-bold text-white text-lg">Phase 2: Check Every PR</h3>
          </div>
          <p className="text-xs text-slate-400">
            Runs deterministically in CI on every incoming Pull Request (No LLM in verdict).
          </p>

          <ol className="space-y-3 text-xs text-slate-300">
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-emerald-300 block">1. Babel AST & Call Graph Engine</span>
              Parses changed files and constructs lexical scopes and reachability paths.
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-emerald-300 block">2. Invariant Verification</span>
              Tests whether every path to sensitive sinks passes through the dominating guard.
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-emerald-300 block">3. Inverse-Patch Similarity Check</span>
              Spots stealthy partial reverts hidden inside benign-looking refactors.
            </li>
            <li className="p-3 bg-slate-900 rounded-lg border border-slate-800">
              <span className="font-semibold text-emerald-300 block">4. Deterministic PR Comment Bot</span>
              Outputs exact line-numbered traceback and remediation links.
            </li>
          </ol>
        </div>
      </div>

      {/* The 4 Invariant Templates */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="font-bold text-white text-lg flex items-center gap-2">
          <Terminal className="w-5 h-5 text-purple-400" />
          The 4 Supported Invariant Templates
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-rose-400">1. Guard Removal</div>
            <p className="text-slate-400">
              Detects when an <code>if (!isSafe) return</code> check is directly deleted in git diffs.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-amber-400">2. Guard Bypass</div>
            <p className="text-slate-400">
              Detects when a refactored helper function or new route allows reaching the sink without the guard.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-purple-400">3. Sanitizer Swap</div>
            <p className="text-slate-400">
              Detects when a required escaping function (e.g. <code>shellEscape</code>) is removed or swapped.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-cyan-400">4. Inverse Patch</div>
            <p className="text-slate-400">
              Detects when a PR diff is mathematically similar to undoing the lines added in the fix commit.
            </p>
          </div>
        </div>
      </div>

      {/* Comparison with Existing Tools */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="font-bold text-white text-lg">Why Existing Review and Scanners Miss Regressions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-300">
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
            <div className="font-bold text-slate-200 mb-1">Dependabot & Snyk</div>
            <p className="text-slate-400">
              Only check package version strings in <code>package.json</code>. They cannot inspect PR code changes or internal logic.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
            <div className="font-bold text-slate-200 mb-1">CodeQL & SAST</div>
            <p className="text-slate-400">
              Only flag patterns if someone wrote a custom rule for that exact bug. They have no institutional memory of past fixes.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
            <div className="font-bold text-cyan-300 mb-1">PATCHBACK (Our Innovation)</div>
            <p className="text-slate-400">
              Remembers the historical intent of every fix. Enforces invariant dominance automatically on every PR in &lt;10ms.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
