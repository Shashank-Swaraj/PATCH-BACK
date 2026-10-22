# 📽️ Slide Deck Outline (For AVISHKAR Hackathon Pitch)

**Owner:** Nikitah (`feature/pitch-benchmark` branch)

Use this outline to design our presentation slides on PowerPoint / Canva / Google Slides:

---

### Slide 1: Title & Hook
* **Title:** PATCHBACK
* **Tagline:** Security Regression Intelligence for Open-Source Packages
* **Hook:** *"Fixed vulnerabilities can silently come back."*
* **The Story:** In 2006, OpenSSH patched a critical vulnerability (CVE-2006-5051). In 2020, an innocent code refactor removed the mitigation directive. In 2024, it was disclosed as **regreSSHion (CVE-2024-6387)**—a remote code execution flaw that went unnoticed for 4 years!
* **Team:** Lead (AST Engine), Suhani (Security Testbed), Sanjana (Frontend), Nikitah (Benchmark & Pitch).

---

### Slide 2: The Blind Spot (Why Existing Tools Fail)
* **1. Dependabot & Snyk:** Only inspect `package.json` version strings. They cannot scan internal custom code refactors.
* **2. Traditional SAST / CodeQL:** Operates on generic pattern rules. Has no historical memory of past repo-specific fixes.
* **3. Code Reviewers:** Reviewers see only diff hunks (`+` and `-`). Nobody remembers why a 3-line check was added 2 years ago.

---

### Slide 3: Our Solution: PATCHBACK
* **The Concept:** Turn historical security patches into permanent **Security Invariants** stored in a "Patch Memory."
* **Core Rule:** *"The LLM proposes the invariant, but deterministic code decides the PR verdict."*
* When a PR is opened, PATCHBACK verifies that required defensive guards dominate all paths to sensitive sinks.

---

### Slide 4: Empirical Benchmark Results
| Metric | Result | Benchmark Significance |
| :--- | :--- | :--- |
| **Regression Detection Rate** | **100% (4/4)** | Caught Guard Bypass, Removal, and Reverts |
| **False Alarm Rate** | **0.0% (0/2)** | Benign cleanups & refactors pass cleanly |
| **Analysis Latency** | **< 5ms** | Fast enough to run seamlessly in any CI pipeline |

---

### Slide 5: Live Demo & Future Scope
* **Live Demo:** Running the simulation on Express Path Traversal & Command Injection.
* **Adoption:** Distributed as a single GitHub Action (`.github/workflows/patchback.yml`).
* **Roadmap:** npm/JavaScript (Now) ➔ Python/PyPI (Next) ➔ Community Patch Memory Registry.
