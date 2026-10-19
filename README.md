# 🛡️ PATCHBACK

> **Security Regression Intelligence for Open-Source Packages**  
> *"Remember the fix. Protect the future."*  
> **FET Hackathon (AVISHKAR) • Jain Deemed-to-be University**

---

## 📌 Executive Summary

Fixed vulnerabilities often silently return years later during refactoring, cleanups, or merge conflicts (such as the real-world **`regreSSHion` CVE-2024-6387** that went unnoticed in OpenSSH for nearly 4 years).

Existing tools fail because:
- **Dependabot / Snyk**: Only check `package.json` version numbers, not custom code removing past defenses.
- **CodeQL / SAST**: Require writing a custom query for every specific vulnerability pattern.
- **Human Reviewers**: Only see the pull request diff, without knowing historical context of *why* a particular 3-line check was added years ago.

**PATCHBACK** captures the historical intent of past security fixes as **Typed Security Invariants**, validates them through a machine **Sanity Gate**, and deterministically evaluates Pull Requests in CI in **under 10ms** with zero AI hallucinations in the pass/fail loop.

---

## 🏛️ System Architecture: *"LLM Proposes, Code Decides"*

```
                                      PATCHBACK WORKFLOW
                                      
  [Phase 1: Learn Once Per Fix]
  Advisory (GHSA/OSV) + Patch Commit
                  │
                  ▼
        LLM Template Ingestion (Assistive)
                  │
                  ▼
         Candidate Invariant
                  │
                  ▼
         ┌───────────────────┐
         │    SANITY GATE    │   Must FAIL on vulnerable code
         │ (Static Analysis) │   Must PASS on fixed code
         └─────────┬─────────┘
                   │ Verified
                   ▼
       [ Patch Memory Store ] (SQLite / JSON)
                   │
                   │ Invariant Rules
                   ▼
  [Phase 2: Check Every PR in CI (Deterministic)]
  Pull Request Diff + AST Parser (Babel / Tree-sitter)
                  │
                  ▼
         Call Graph & Reachability Engine
                  │
                  ▼
         ┌────────────────────────────────────────────────────────┐
         │              INVARIANT EVALUATION SUITE                │
         │  1. Guard Dominance    2. Guard Removal                │
         │  3. Sanitizer Swap     4. Inverse-Patch Similarity     │
         └────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
         ┌────────────────────────────────────────────────────────┐
         │             EVIDENCE & VERDICT GENERATION              │
         │  Verdict: PROVEN | LIKELY | REVIEW | BENIGN            │
         │  Trace: routes.js:41 ──> assets.js:12 ──> sendFile()   │
         │  GitHub PR Comment with direct link to original CVE    │
         └────────────────────────────────────────────────────────┘
```

---

## 📦 Project Structure

```
AVISHKAR/
├── packages/
│   ├── core/                  # Core Engine
│   │   ├── src/
│   │   │   ├── ast/           # AST parser, traversal, and Lexical Control Flow Graph
│   │   │   ├── invariants/    # Guard Dominance, Guard Removal, Sanitizer Swap, Inverse Patch
│   │   │   ├── memory/        # Patch Memory Store (Advisories & Invariants)
│   │   │   ├── sanity-gate/   # Machine validation gate for candidate invariants
│   │   │   ├── reporter/      # GitHub Action markdown comment generator
│   │   │   └── engine.ts      # Main PR Scanner Engine
│   │   └── test/              # Vitest test suite and official benchmark
│   │
│   ├── fixtures/              # Curated Real/Seeded CVE & Regression Scenarios
│   │   ├── src/scenarios.ts   # Express Path Traversal, Command Injection, Prototype Pollution, Revert, Benign
│   │
│   ├── cli/                   # CLI runner
│   │   └── src/index.ts       # `patchback benchmark`, `patchback demo`
│   │
│   └── web/                   # Full-Stack Interactive Testing Website & Live Simulation
│       ├── server.js          # Express API server (port 3001)
│       └── src/               # React 19 + Tailwind Cyber UI dashboard
```

---

## 🚀 Quickstart & How to Run

### 1. Run the Full-Stack Simulation Dashboard
```bash
# Starts both the backend API and serves the dark-mode cyber simulation UI
npm run server -w @patchback/web
```
Open **`http://localhost:3001`** in your browser.

### 2. Run the Benchmark Suite via CLI
```bash
npm run benchmark -w @patchback/core
```
Or use the CLI command:
```bash
node packages/cli/dist/index.js benchmark
```

### 3. Run the Pitch Deck Interactive Walkthrough
```bash
node packages/cli/dist/index.js demo
```

---

## 📊 Benchmark Results

| Vulnerability Category | Expected Verdict | PATCHBACK Verdict | Latency | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Express Path Traversal (Pitch Deck Case)** | `PROVEN` | `PROVEN` | ~17ms | ✅ PASS |
| **Command Injection Sanitizer Swap** | `PROVEN` | `PROVEN` | ~2ms | ✅ PASS |
| **Prototype Pollution Guard Removal** | `PROVEN` | `PROVEN` | ~2ms | ✅ PASS |
| **Merge Conflict Accidental Revert** | `PROVEN` | `PROVEN` | ~1ms | ✅ PASS |
| **Benign Refactor: Code Cleanup & Renaming** | `BENIGN` | `BENIGN` | ~2ms | ✅ PASS |
| **Benign Addition: New Unrelated Endpoint** | `BENIGN` | `BENIGN` | ~2ms | ✅ PASS |

- 🎯 **Detection Rate:** **100.0%** (All regressions caught)
- 🛡️ **False Alert Rate:** **0.0%** (Zero false alarms on benign cleanups)
- ⚡ **Average Latency:** **~4.45ms per PR** in CI
