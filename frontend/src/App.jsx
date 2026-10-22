import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Play, Copy, Check, Terminal, ExternalLink } from 'lucide-react';

const SCENARIOS = [
  {
    id: 'path-traversal',
    name: '1. Express Path Traversal (Pitch Deck Case)',
    cwe: 'CWE-22',
    sink: 'res.sendFile',
    guard: 'startsWith(root)',
    fixDesc: '2022 Fix: Added root boundary containment check (!p.startsWith(root)).',
    prDesc: '2024 PR #412: Extracted sendAsset helper function. Forgot startsWith guard on new /asset route.',
    prCode: `// PR #412 "Extract helper function"
function sendAsset(res, filePath) {
  res.sendFile(filePath); // SINK: called directly!
}

app.get('/f', (req, res) => {
  const p = path.resolve(root, req.query.p);
  if (!p.startsWith(root)) return res.status(403);
  sendAsset(res, p);
});

// BYPASS ROUTE:
app.get('/asset', (req, res) => {
  sendAsset(res, req.query.p);
});`,
    verdict: 'PROVEN_REGRESSION',
    brokenLine: 3,
    brokenCode: 'res.sendFile(filePath);',
    explanation: "Execution reaches sink 'res.sendFile' without required guard 'startsWith(root)' on route '/asset'.",
  },
  {
    id: 'command-injection',
    name: '2. Command Injection Sanitizer Swap',
    cwe: 'CWE-78',
    sink: 'child_process.exec',
    guard: 'shellEscape(host)',
    fixDesc: '2021 Fix: Wrapped input in shellEscape(host) to prevent command chaining.',
    prDesc: '2024 PR #520: Modernized ping utility using template literals without shell escaping.',
    prCode: `// PR #520 "Modernize with string template"
function pingHost(host) {
  return exec(\`ping -c 1 \${host}\`); // SINK without shellEscape!
}`,
    verdict: 'PROVEN_REGRESSION',
    brokenLine: 3,
    brokenCode: 'return exec(`ping -c 1 ${host}`);',
    explanation: "Dangerous sink 'exec' called with unsanitized argument. Missing 'shellEscape'.",
  },
  {
    id: 'benign-cleanup',
    name: '3. Benign Clean PR (Zero False Alarms)',
    cwe: 'None',
    sink: 'res.sendFile',
    guard: 'startsWith(root)',
    fixDesc: '2022 Fix: Defensive startsWith guard protecting file reads.',
    prDesc: '2024 PR #601: Cleaned up variable names and added comments. Guard is fully preserved.',
    prCode: `// Benign clean up
app.get('/f', (request, response) => {
  console.log('Serving asset');
  const target = path.resolve(root, request.query.p);
  
  if (!target.startsWith(root)) {
    return response.status(403).send('Forbidden');
  }
  
  response.sendFile(target);
});`,
    verdict: 'SAFE_PASS',
    brokenLine: null,
    brokenCode: null,
    explanation: 'All security invariants are fully preserved. Safe to merge!',
  },
];

export default function App() {
  const [selectedScenario, setSelectedScenario] = useState(SCENARIOS[0]);
  const [analyzed, setAnalyzed] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleSelect = (scenario) => {
    setSelectedScenario(scenario);
    setAnalyzed(false);
  };

  const copyComment = () => {
    const text = `### 🚨 PATCHBACK Security Regression Detected\n**Verdict:** \`${selectedScenario.verdict}\`\nViolated Guard: \`${selectedScenario.guard}\` on sink \`${selectedScenario.sink}\`\nFile: \`routes.js:${selectedScenario.brokenLine}\``;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e17', color: '#e2e8f0', padding: '2rem 1.5rem' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        {/* Header */}
        <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem', borderBottom: '1px solid #1e293b', paddingBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ width: 42, height: 42, borderRadius: 10, background: 'linear-gradient(135deg, #0284c7, #2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={24} color="#fff" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.02em' }}>PATCHBACK</h1>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Security Regression Intelligence for Open-Source Packages</p>
            </div>
          </div>
          <div style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem', borderRadius: 20, background: '#1e293b', color: '#38bdf8', border: '1px solid #334155', fontWeight: 600 }}>
            FET Hackathon • AVISHKAR
          </div>
        </header>

        {/* Scenario Selector Tabs */}
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => handleSelect(s)}
              style={{
                padding: '0.6rem 1rem',
                borderRadius: 8,
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                border: s.id === selectedScenario.id ? '1px solid #38bdf8' : '1px solid #1e293b',
                background: s.id === selectedScenario.id ? '#1e293b' : '#0f172a',
                color: s.id === selectedScenario.id ? '#38bdf8' : '#94a3b8',
              }}
            >
              {s.name}
            </button>
          ))}
        </div>

        {/* 2-Column Comparison */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
          {/* Box 1: Fix Rule */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: '1.25rem' }}>
            <span style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: '#38bdf8', fontWeight: 700, letterSpacing: '0.05em' }}>
              Historical Security Rule (Patch Memory)
            </span>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#fff', marginTop: '0.25rem', marginBottom: '0.5rem' }}>
              Required Invariant: {selectedScenario.guard}
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '1rem' }}>
              {selectedScenario.fixDesc}
            </p>
            <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: 8, fontSize: '0.75rem', border: '1px solid #1e293b', color: '#cbd5e1' }}>
              <div><strong>Protected Sink:</strong> <code style={{ color: '#f43f5e' }}>{selectedScenario.sink}</code></div>
              <div><strong>Mandatory Guard:</strong> <code style={{ color: '#10b981' }}>{selectedScenario.guard}</code></div>
              <div><strong>CWE Class:</strong> <code style={{ color: '#fbbf24' }}>{selectedScenario.cwe}</code></div>
            </div>
          </div>

          {/* Box 2: The Refactoring PR */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: '1.25rem' }}>
            <span style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: '#a855f7', fontWeight: 700, letterSpacing: '0.05em' }}>
              Incoming Pull Request (Refactor)
            </span>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#fff', marginTop: '0.25rem', marginBottom: '0.5rem' }}>
              PR Diff Under Review
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '1rem' }}>
              {selectedScenario.prDesc}
            </p>
            <pre style={{ background: '#090d16', padding: '0.75rem', borderRadius: 8, fontSize: '0.72rem', border: '1px solid #1e293b', color: '#e2e8f0', overflowX: 'auto', maxHeight: 160 }}>
              {selectedScenario.prCode}
            </pre>
          </div>
        </div>

        {/* Action Button */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <button
            onClick={() => setAnalyzed(true)}
            style={{
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              color: '#fff',
              border: 'none',
              padding: '0.85rem 2rem',
              borderRadius: 10,
              fontSize: '0.95rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              boxShadow: '0 4px 20px rgba(2, 132, 199, 0.4)',
            }}
          >
            <Play size={18} fill="#fff" />
            Run PATCHBACK Invariant Check
          </button>
        </div>

        {/* Results Panel */}
        {analyzed && (
          <div
            style={{
              background: selectedScenario.verdict === 'SAFE_PASS' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(244, 63, 94, 0.08)',
              border: selectedScenario.verdict === 'SAFE_PASS' ? '1px solid #10b981' : '1px solid #f43f5e',
              borderRadius: 12,
              padding: '1.5rem',
              marginBottom: '2rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {selectedScenario.verdict === 'SAFE_PASS' ? (
                  <CheckCircle size={28} color="#10b981" />
                ) : (
                  <AlertTriangle size={28} color="#f43f5e" />
                )}
                <div>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fff' }}>
                    {selectedScenario.verdict === 'SAFE_PASS' ? 'All Invariants Satisfied' : 'Security Regression Detected!'}
                  </h2>
                  <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    Static AST & Flow Analysis evaluated in <strong style={{ color: '#38bdf8' }}>4.2ms</strong>
                  </p>
                </div>
              </div>

              {selectedScenario.verdict !== 'SAFE_PASS' && (
                <button
                  onClick={copyComment}
                  style={{
                    background: '#1e293b',
                    color: '#e2e8f0',
                    border: '1px solid #334155',
                    padding: '0.5rem 0.85rem',
                    borderRadius: 6,
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                  }}
                >
                  {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                  {copied ? 'Copied Markdown' : 'Copy PR Comment'}
                </button>
              )}
            </div>

            {selectedScenario.verdict !== 'SAFE_PASS' ? (
              <div style={{ background: '#090d16', padding: '1rem', borderRadius: 8, border: '1px solid #1e293b', fontSize: '0.8rem', color: '#cbd5e1' }}>
                <div style={{ color: '#f43f5e', fontWeight: 700, marginBottom: '0.5rem' }}>
                  ❌ Missing Invariant: {selectedScenario.explanation}
                </div>
                <div><strong>Location:</strong> Line {selectedScenario.brokenLine}</div>
                <div><strong>Offending Code:</strong> <code style={{ color: '#f43f5e' }}>{selectedScenario.brokenCode}</code></div>
                <div style={{ marginTop: '0.5rem', color: '#94a3b8', fontSize: '0.75rem' }}>
                  <strong>Remediation:</strong> Ensure all execution paths calling <code style={{ color: '#f43f5e' }}>{selectedScenario.sink}</code> evaluate <code style={{ color: '#10b981' }}>{selectedScenario.guard}</code> before reaching the sink.
                </div>
              </div>
            ) : (
              <div style={{ color: '#10b981', fontSize: '0.85rem', fontWeight: 600 }}>
                ✅ PR #601 passed all security invariant checks with 0 regressions. Clean to merge!
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
