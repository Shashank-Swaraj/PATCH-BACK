import React, { useEffect, useState } from 'react';
import { Database, Shield, Lock, FileCode, CheckCircle, Search } from 'lucide-react';

export const PatchMemoryView: React.FC = () => {
  const [data, setData] = useState<{ invariants: any[]; advisories: any[] }>({
    invariants: [],
    advisories: [],
  });
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetch('/api/invariants')
      .then((res) => res.json())
      .then((resData) => setData(resData))
      .catch((err) => console.error('Failed to load invariants:', err));
  }, []);

  const filteredInvariants = data.invariants.filter(
    (inv) =>
      inv.id.toLowerCase().includes(filter.toLowerCase()) ||
      inv.packageName.toLowerCase().includes(filter.toLowerCase()) ||
      inv.type.toLowerCase().includes(filter.toLowerCase()) ||
      inv.vulnerabilityType.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-6 h-6 text-cyan-400" />
            <h2 className="text-2xl font-bold text-white">Patch Memory Store</h2>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Institutional memory of past vulnerabilities, historical fix commits, and machine-validated security invariants.
          </p>
        </div>

        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search invariants or packages..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-sm rounded-lg pl-9 pr-4 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500 w-72"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredInvariants.map((inv) => {
          const advisory = data.advisories.find((a) => a.id === inv.advisoryId);

          return (
            <div key={inv.id} className="glass-panel p-5 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-mono font-semibold">
                    {inv.type}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {inv.packageName}
                  </span>
                </div>

                <div>
                  <h3 className="font-bold text-white text-base font-mono">
                    {inv.id}
                  </h3>
                  <div className="text-xs text-rose-400 font-semibold mt-0.5">
                    {inv.vulnerabilityType}
                  </div>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 text-xs font-mono text-slate-300 space-y-1">
                  {inv.type === 'GUARD_DOMINATES' && (
                    <>
                      <div><span className="text-slate-500">sink:</span> <span className="text-rose-300">{inv.params.sink}</span></div>
                      <div><span className="text-slate-500">guard:</span> <span className="text-emerald-300">{inv.params.guard}</span></div>
                      <div><span className="text-slate-500">source:</span> <span className="text-amber-300">{inv.params.source}</span></div>
                    </>
                  )}
                  {inv.type === 'SANITIZER_SWAP' && (
                    <>
                      <div><span className="text-slate-500">sink:</span> <span className="text-rose-300">{inv.params.sink}</span></div>
                      <div><span className="text-slate-500">sanitizer:</span> <span className="text-emerald-300">{inv.params.requiredSanitizer}</span></div>
                    </>
                  )}
                  {inv.type === 'GUARD_REMOVAL' && (
                    <div><span className="text-slate-500">guard:</span> <span className="text-emerald-300">{inv.params.guard}</span></div>
                  )}
                  {inv.type === 'INVERSE_PATCH' && (
                    <div><span className="text-slate-500">threshold:</span> <span className="text-cyan-300">{inv.params.similarityThreshold * 100}%</span></div>
                  )}
                </div>

                <p className="text-xs text-slate-400 line-clamp-2">
                  {inv.rationale}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-500">Commit: <span className="font-mono text-slate-300">{inv.fixCommitSha}</span></span>
                <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                  <CheckCircle className="w-3.5 h-3.5" /> Enforced
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
