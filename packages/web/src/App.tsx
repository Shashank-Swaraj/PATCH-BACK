import React, { useState } from 'react';
import { Navbar } from './components/Navbar.js';
import { SimulatorView } from './components/SimulatorView.js';
import { PatchMemoryView } from './components/PatchMemoryView.js';
import { BenchmarkView } from './components/BenchmarkView.js';
import { ArchitectureView } from './components/ArchitectureView.js';

export default function App() {
  const [activeTab, setActiveTab] = useState('simulator');

  return (
    <div className="min-h-screen flex flex-col bg-[#080d1a] text-slate-100">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="flex-1 pb-16">
        {activeTab === 'simulator' && <SimulatorView />}
        {activeTab === 'memory' && <PatchMemoryView />}
        {activeTab === 'benchmark' && <BenchmarkView />}
        {activeTab === 'architecture' && <ArchitectureView />}
      </main>

      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-400 bg-slate-950/60">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            <span className="font-semibold text-slate-300">PATCHBACK</span> — Security Regression Intelligence for Open-Source Packages
          </div>
          <div className="text-slate-400">
            FET Hackathon (AVISHKAR) • Jain Deemed-to-be University
          </div>
        </div>
      </footer>
    </div>
  );
}
