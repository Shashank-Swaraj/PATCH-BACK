# 🛡️ PATCHBACK

> **Security Regression Intelligence for Open-Source Packages**  
> *"Remember the fix. Protect the future."*  
> **AVISHKAR FET Hackathon • Jain (Deemed-to-be University)**

---

## 📌 Executive Summary

When an open-source project or enterprise codebase patches a security vulnerability, developers write defensive guards (such as input validation, path boundary checks, or shell escaping).

However, **codebases constantly evolve**. Months or years later, developers refactor, clean up legacy code, or resolve merge conflicts—and **accidentally delete, bypass, or forget those defensive security checks**.

* **Real-World Case Study — regreSSHion ([CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)):** OpenSSH patched a critical remote code execution flaw in 2006. In 2020, an innocent code refactor accidentally removed the mitigation directive. The vulnerability silently resurfaced and remained exposed for **4 whole years**, putting millions of public Linux servers at risk!

---

## 🔍 The Blind Spot: Why Existing Tools Fail

| Tool Category | How It Operates | Why It Misses Logic Regressions |
| :--- | :--- | :--- |
| **Dependabot & Snyk** | Scans dependency versions | Only inspects `package.json` version strings. Completely blind to logic refactors inside custom code. |
| **Traditional SAST / CodeQL** | Scans generic patterns | Lacks repository-specific historical memory of *why* a particular 3-line check was added in this project years ago. |
| **Human Code Reviewers** | Scans PR diff hunks | Reviewers only see isolated `+` and `-` lines without historical context. Moving code to a helper function easily conceals a deleted CVE guard. |

---

## 💡 The Solution: PATCHBACK

**PATCHBACK** acts as an automated, permanent **Security Memory** for software repositories:
1. It translates past CVE fixes into machine-verifiable **Typed Security Invariants**.
2. It verifies every incoming Pull Request in CI via deterministic Abstract Syntax Tree (AST) analysis.
3. It guarantees that security checks are never removed or bypassed during refactors.

> 🧠 **Core Guiding Principle:**  
> *"The LLM proposes the invariant, but deterministic code decides the PR verdict."*  
> By strictly separating rule generation from deterministic AST verification, PATCHBACK runs in **under 10ms** in CI with **zero AI hallucinations** in the pass/fail gate.

---

## 🏛️ System Architecture & Workflow

```
                                      PATCHBACK WORKFLOW
                                      
  [Phase 1: Learn Once Per Fix]
  Advisory (GHSA/CVE) + Patch Commit
                  │
                  ▼
        LLM Template Ingestion (Assistive)
                  │
                  ▼
         ┌───────────────────┐
         │    SANITY GATE    │   Must FAIL on vulnerable code (Red)
         │ (Static Analysis) │   Must PASS on fixed code (Green)
         └─────────┬─────────┘
                   │ Verified
                   ▼
       [ Patch Memory Store ] (JSON / Ruleset DB)
                   │
                   │ Invariant Rules
                   ▼
  [Phase 2: Check Every PR in CI (Deterministic)]
  Pull Request Diff + AST Parser (@babel/parser)
                  │
                  ▼
      Call Graph & Control Flow Reachability
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
         │  Verdict: SAFE_PASS (Green) | PROVEN_REGRESSION (Red)  │
         │  Trace: File & line numbers, missing guard, CVE link   │
         │  Simulated Automated GitHub PR Comment                 │
         └────────────────────────────────────────────────────────┘
```

---

## 🔬 The 4 Invariant Enforcement Engines

1. **Guard Dominance Checker:** Traces AST call paths to dangerous *sinks* (e.g. `res.sendFile`, `child_process.exec`) and proves mathematically that an authorized *guard* (e.g. `.startsWith(safeRoot)`) dominates that execution path.
2. **Guard Removal Checker:** Scans PR diffs for deleted defensive `if` conditions that match historical patch rules.
3. **Sanitizer Swap Checker:** Flags when a robust sanitizer (e.g. `shellEscape(arg)`) is replaced with an unsafe alternative (e.g. ES6 template string interpolation `` `ping ${arg}` ``).
4. **Inverse-Patch Detection:** Detects when a rebase or merge conflict accidentally un-applies changes made by an earlier security patch commit.

---

## 👥 Team & Folder Assignments

| Member | Role | Assigned Folder | Feature Branch |
| :--- | :--- | :--- | :--- |
| **Shashank** | Core Engine & AST Analyzer (Lead) | `engine/` | `main` |
| **Suhani** | Security Testbed & CVE Scenarios | `scenarios/` | `feature/scenarios` |
| **Sanjana** | Frontend & Interactive UI | `frontend/` | `feature/frontend` |
| **Nikitah** | Integration, Benchmark & Pitch | `pitch-and-benchmark/` | `feature/pitch-benchmark` |

### 📁 Repository Structure Overview

```
AVISHKAR/
├── engine/                 # 👤 Shashank: AST parser & guard reachability checker
├── scenarios/              # 👤 Suhani: Vulnerable, patched, and broken PR test fixtures
├── frontend/               # 👤 Sanjana: React + Vite web dashboard for live demo
└── pitch-and-benchmark/    # 👤 Nikitah: Presentation slides, script & benchmark runner
```

---

## 🚀 Getting Started & Team Workflow

### Step 1: Clone the repository
```bash
git clone <GITHUB-REPO-URL>
cd AVISHKAR
```

### Step 2: Switch to your team branch
* **If you are Suhani:** `git checkout -b feature/scenarios`
* **If you are Sanjana:** `git checkout -b feature/frontend`
* **If you are Nikitah:** `git checkout -b feature/pitch-benchmark`

### Step 3: Push changes and open a PR
```bash
git add .
git commit -m "feat: completed my assigned component"
git push origin <your-branch-name>
```

---

## 📊 Empirical Benchmark Results

| Scenario | Attack Class | Target Sink | Required Guard | Expected | PATCHBACK Verdict | Latency | Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Express File Server** | Path Traversal | `res.sendFile` | `safePath.startsWith` | `REGRESSION` | `PROVEN_REGRESSION` | ~3.8ms | ✅ Caught |
| **Ping Tool** | Command Injection | `child_process.exec` | `shellEscape` | `REGRESSION` | `PROVEN_REGRESSION` | ~2.1ms | ✅ Caught |
| **Config Merger** | Prototype Pollution | `target[key]` | `key !== '__proto__'` | `REGRESSION` | `PROVEN_REGRESSION` | ~1.9ms | ✅ Caught |
| **Git Merge Revert** | Accidental Revert | `authMiddleware` | `verifyToken` | `REGRESSION` | `PROVEN_REGRESSION` | ~1.4ms | ✅ Caught |
| **Refactor Cleanup** | Benign Refactor | `res.sendFile` | `safePath.startsWith` | `SAFE_PASS` | `SAFE_PASS` | ~2.2ms | ✅ Passed |
| **New Route Addition**| Benign Addition | `res.json` | None (Unrelated) | `SAFE_PASS` | `SAFE_PASS` | ~1.8ms | ✅ Passed |

* 🎯 **Regression Detection Rate:** **100.0%** (All regressions caught)
* 🛡️ **False Positive Rate:** **0.0%** (Zero false alarms on benign cleanups)
* ⚡ **Average Latency:** **< 5ms** per Pull Request in CI
* 🤖 **Hallucination Rate:** **0.0%** (Fully deterministic AST execution in the PR gate)

---

## 💻 How to Run the Modules

### 1. Test the Core AST Engine (`engine/`)
```bash
cd engine
npm install
node test-demo.js
```

### 2. Run the Benchmark Scorecard (`pitch-and-benchmark/`)
```bash
cd pitch-and-benchmark
node benchmark-runner.js
```

### 3. Launch the Presentation Dashboard (`frontend/`)
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser to view the interactive demo dashboard.

---

## ⏱️ 3-Minute Live Presentation Flow for Judges

| Time | Speaker | Topic & Action | What Judges See |
| :---: | :--- | :--- | :--- |
| **0:00 – 0:45** | **Nikitah** | **The Hook:** Introduce regreSSHion (CVE-2024-6387). Explain why Dependabot and CodeQL fail to catch logic regressions. | Slide 1 & 2: The OpenSSH 4-year regression story |
| **0:45 – 1:30** | **Shashank** | **The Architecture:** Explain *"LLM proposes, code decides"*, the machine Sanity Gate, and deterministic AST verification in < 5ms. | Slide 3: Architecture Diagram & AST traversal |
| **1:30 – 2:30** | **Suhani & Sanjana** | **Live Interactive Demo:** Suhani explains the Express Path Traversal scenario; Sanjana clicks *"Run Invariant Check"*. The UI immediately highlights the missing guard and shows the simulated GitHub PR block. | Live Dashboard: Side-by-side diff + Red Alert card |
| **2:30 – 3:00** | **Nikitah** | **The Benchmark & Close:** Present the 100% detection rate and 0% false positive benchmark scorecard. Close with tagline: *"Remember the fix. Protect the future."* | Benchmark Scorecard Table & GitHub Action roadmap |

---

## 🔮 Future Roadmap

* [x] **v1.0 (Hackathon MVP):** JavaScript/Node.js AST engine (`@babel/parser`), 4 core invariant checkers, interactive React demo UI.
* [ ] **v1.1:** Python (`ast` / LibCST) and Go (`go/ast`) support.
* [ ] **v1.2:** Single-line GitHub Action integration (`.github/workflows/patchback.yml`).
* [ ] **v2.0:** Community-driven global Patch Memory Registry for top open-source repositories.
