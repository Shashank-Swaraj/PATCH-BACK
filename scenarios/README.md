# 🛡️ Security Scenarios & Testbed (`scenarios/`)

**Owner:** Suhani (`feature/scenarios` branch)

## What this module does:
This folder stores our benchmark scenarios. Each file represents a real-world vulnerability pattern containing 3 states of code:
1. **The Bug (Vulnerable Code):** How the app originally looked when unsafe.
2. **The Fix (Patched Code):** How the security patch fixed it by adding a guard.
3. **The Regression PR (Broken Refactor):** An innocent-looking pull request that accidentally removed or bypassed the guard.

## Scenarios Created:
* `01-path-traversal.js`: Express file server path traversal (CWE-22).
* `02-command-injection.js`: System ping command injection (CWE-78).
* `03-benign-clean-pr.js`: Safe code cleanup to prove **0% false alarms** on good PRs.

## How Suhani can test her scenarios:
Run any scenario with Node:
```bash
node scenarios/01-path-traversal.js
```
