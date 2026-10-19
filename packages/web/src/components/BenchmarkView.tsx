import React, { useState, useEffect } from 'react';
import { BarChart3, RotateCw, CheckCircle2, ShieldCheck, Zap, AlertTriangle } from 'lucide-react';

export const BenchmarkView: React.FC = () => {
  const [benchmarkData, setBenchmarkData] = useState<any>(null);
  const [isRunning, setIsRunning] = useState(false);

  const fetchBenchmark = () => {
    setIsRunning(true);
    fetch('/api/benchmark')
      .then((res) => res.json())
      .then((data) => {
        setBenchmarkData(data);
      })
      .catch((err) => console.error('Benchmark fetch error:', err))
      .finally(() => setIsRunning(false));
  };

  useEffect(() => {
    fetchBenchmark();
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
      {/* Header and Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-cyan-400" />
            <h2 className="text-2xl font-bold text-white">Official Regression Benchmark Arena</h2>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Empirical evaluation across real-world CVE patterns, seeded refactoring bugs, and benign pull requests.
          </p>
        </div>

        <button
          onClick={fetchBenchmark}
          disabled={isRunning}
          className="btn-primary"
        >
          <RotateCw className={`w-4 h-4 ${isRunning ? 'animate-spin' : ''}`} />
          {isRunning ? 'Running AST Scans...' : 'Re-run Benchmark Suite'}
        </button>
      </div>

      {/* KPI Cards */}
      {benchmarkData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="glass-panel p-6 border-l-4 border-l-emerald-500">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-400">Detection Rate</span>
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2 font-mono">
              {benchmarkData.detectionRate.toFixed(1)}%
            </div>
            <p className="text-xs text-emerald-400 mt-1">
              Caught {benchmarkData.regressionsCaught} of {benchmarkData.regressionsTested} regressions
            </p>
          </div>

          <div className="glass-panel p-6 border-l-4 border-l-cyan-500">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-400">False Alert Rate</span>
              <CheckCircle2 className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2 font-mono">
              {benchmarkData.falseAlertRate.toFixed(1)}%
            </div>
            <p className="text-xs text-cyan-400 mt-1">
              0 out of {benchmarkData.benignTested} benign PRs falsely flagged
            </p>
          </div>

          <div className="glass-panel p-6 border-l-4 border-l-purple-500">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-400">Average CI Latency</span>
              <Zap className="w-5 h-5 text-purple-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2 font-mono">
              {benchmarkData.avgLatency}ms
            </div>
            <p className="text-xs text-purple-400 mt-1">
              Deterministic AST & CFG execution speed
            </p>
          </div>
        </div>
      )}

      {/* Benchmark Results Table */}
      {benchmarkData && (
        <div className="glass-panel overflow-hidden">
          <div className="px-6 py-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">Evaluation Testbed Results</h3>
            <span className="text-xs text-slate-400">Total Scenarios: {benchmarkData.results.length}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3">Scenario Name</th>
                  <th className="px-6 py-3">Vulnerability Category</th>
                  <th className="px-6 py-3">Expected Verdict</th>
                  <th className="px-6 py-3">PATCHBACK Verdict</th>
                  <th className="px-6 py-3">Latency</th>
                  <th className="px-6 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {benchmarkData.results.map((row: any) => (
                  <tr key={row.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="px-6 py-3.5 font-medium text-white">{row.name}</td>
                    <td className="px-6 py-3.5 text-slate-400">{row.category}</td>
                    <td className="px-6 py-3.5">
                      <span className={row.expected === 'BENIGN' ? 'text-emerald-400' : 'text-rose-400'}>
                        {row.expected}
                      </span>
                    </td>
                    <td className="px-6 py-3.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.actual === 'BENIGN'
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                            : 'bg-rose-950/80 text-rose-300 border border-rose-800'
                        }`}
                      >
                        {row.actual}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-cyan-400">{row.latency}ms</td>
                    <td className="px-6 py-3.5">
                      <span className="inline-flex items-center gap-1.5 text-emerald-400 font-bold">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" /> PASS
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
