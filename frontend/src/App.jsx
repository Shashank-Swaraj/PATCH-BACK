import React, { useState } from 'react';

// TODO: Sanjana - Build your interactive dashboard from scratch here!
export default function App() {
  return (
    <div style={{ maxWidth: 900, margin: '2rem auto', fontFamily: 'sans-serif', padding: '1rem' }}>
      <header style={{ borderBottom: '1px solid #ccc', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0 }}>🛡️ PATCHBACK Dashboard</h1>
        <p style={{ color: '#666', margin: '0.25rem 0 0 0' }}>
          Security Regression Intelligence for Open-Source Packages
        </p>
      </header>

      <main>
        <section style={{ background: '#f8f9fa', padding: '1.5rem', borderRadius: 8, border: '1px solid #e9ecef' }}>
          <h2>Welcome Sanjana!</h2>
          <p>This is your clean canvas to build the presentation UI for the judges.</p>
          
          <h3>Features to build:</h3>
          <ul>
            <li><strong>1. Scenario Selector:</strong> Dropdown or buttons to pick a scenario (Path Traversal, Command Injection, Clean PR).</li>
            <li><strong>2. Code Comparison:</strong> Side-by-side or stacked view showing the 2022 Fix vs 2024 PR.</li>
            <li><strong>3. Action Button:</strong> A button to "Run PATCHBACK Check".</li>
            <li><strong>4. Alert Card:</strong> A red card showing the regression warning, broken line number, and copy button.</li>
          </ul>
        </section>
      </main>
    </div>
  );
}
