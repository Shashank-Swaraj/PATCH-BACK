# 🎤 3-Minute Presentation Script Template

**Assigned to:** Nikitah (`feature/pitch-benchmark` branch)

Use this outline to write our team's 3-minute pitch script for the AVISHKAR judges:

---

### Part 1: The Problem Hook (45 seconds) — Speaker: Nikitah
- Introduce the real-world **regreSSHion** OpenSSH story (vulnerability patched in 2006, accidentally undone in a 2020 refactor, unnoticed for 4 years).
- Explain why Dependabot and CodeQL fail (Dependabot only reads `package.json` versions; CodeQL has no repo memory).

### Part 2: The Solution & Technical Architecture (45 seconds) — Speaker: Lead
- Introduce **PATCHBACK**: Security Regression Intelligence for open source.
- Explain our thesis: *"LLM proposes the invariant, but deterministic code decides the PR verdict."*
- How it runs in CI in < 10ms with zero hallucinations.

### Part 3: Live Demo (60 seconds) — Speakers: Suhani & Sanjana
- Suhani explains the scenario being tested (Express file server).
- Sanjana shows the live UI: clicking "Run Invariant Check" and showing the red alert on the missing guard.

### Part 4: Benchmark & Conclusion (30 seconds) — Speaker: Nikitah
- Present the scorecard: 100% detection rate on regressions, 0% false alarms on benign cleanups.
- Close with tagline: *"PATCHBACK: Remember the fix. Protect the future."*
