# 🛡️ Security Scenarios & Testbed Module (`scenarios/`)

**Owner:** Suhani (`feature/scenarios` branch)  
**Target:** 6 Scenarios Total (4 Regressions + 2 Benign Controls) to support the Slide 4 Benchmark Scorecard.

---

## 🚦 Scenario Implementation Status (Completed vs. Not Completed)

| # | File Name | Vulnerability Type / Scenario | Expected Verdict | Status |
| :--- | :--- | :--- | :--- | :--- |
| **01** | `01-path-traversal.js` | Express `res.sendFile` Guard Bypass (CWE-22) | `PROVEN_REGRESSION` | ✅ **COMPLETED** |
| **02** | `02-command-injection.js` | `child_process.exec` Sanitizer Swap (CWE-78) | `PROVEN_REGRESSION` | ✅ **COMPLETED** |
| **03** | `03-benign-clean-pr.js` | Path Traversal Variable Renaming | `SAFE_PASS` | ✅ **COMPLETED** |
| **04** | `04-prototype-pollution.js` | Object `__proto__` Guard Deletion (CWE-1321) | `PROVEN_REGRESSION` | ❌ **NOT COMPLETED (TO-DO)** |
| **05** | `05-timing-attack.js` | Revert `crypto.timingSafeEqual` (CWE-208) | `PROVEN_REGRESSION` | ❌ **NOT COMPLETED (TO-DO)** |
| **06** | `06-benign-route-addition.js` | Unrelated Endpoint Addition (`/health`) | `SAFE_PASS` | ❌ **NOT COMPLETED (TO-DO)** |

---

## ✅ Part 1: Completed Scenarios (Great Job!)

The following 3 files have been built and tested:

### 1. `01-path-traversal.js` (Express Path Traversal — CWE-22)
* **Sink:** `res.sendFile(filePath)`
* **Guard:** `safePath.startsWith(root + path.sep)`
* **Regression Caught:** PR moves file serving to a helper function `sendAsset(res, filePath)` without the `startsWith` guard.
* **Verdict:** `PROVEN_REGRESSION`

### 2. `02-command-injection.js` (Command Injection — CWE-78)
* **Sink:** `child_process.exec(cmd)`
* **Guard:** `shellEscape(host)`
* **Regression Caught:** Refactor switches string concatenation to template literals (`` `ping ${host}` ``) and loses `shellEscape`.
* **Verdict:** `PROVEN_REGRESSION`

### 3. `03-benign-clean-pr.js` (Safe Refactor — Zero False Positives)
* **Sink:** `res.sendFile(fileToSend)`
* **Guard:** `safePath.startsWith(root + path.sep)`
* **Result:** Renames variables and cleans formatting while keeping the guard intact.
* **Verdict:** `SAFE_PASS`

---

## ❌ Part 2: Not Completed (Action Items for Suhani)

To achieve the full **6/6 Scorecard on Slide 4**, the following 3 files need to be created:

### 4. `04-prototype-pollution.js` (Guard Removal — CWE-1321)
* **Vulnerability:** Prototype Pollution via Recursive Object Merge (GHSA-2023-45133)
* **Dangerous Sink:** Dynamic property write `target[key] = source[key]`
* **Historical Guard:** `if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;`
* **Regression PR:** Developer cleans up merge loop and accidentally drops the `__proto__` check.
* **Expected Verdict:** `PROVEN_REGRESSION`

### 5. `05-timing-attack.js` (Inverse Patch / Revert — CWE-208)
* **Vulnerability:** Cryptographic Timing Attack in Auth Token Verification (GHSA-2024-11892)
* **Dangerous Sink:** Direct equality comparison on secret tokens (`token === expectedToken`)
* **Historical Guard:** `crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))`
* **Regression PR:** Contributor replaces `crypto.timingSafeEqual` with `===` claiming it's "simpler and faster".
* **Expected Verdict:** `PROVEN_REGRESSION`

### 6. `06-benign-route-addition.js` (New Unrelated Route — Benign Control)
* **Purpose:** Confirms that adding new independent routes never triggers false alarms.
* **PR Code:** Contributor adds an innocent health-check route:
  ```javascript
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
  });
  ```
* **Expected Verdict:** `SAFE_PASS`

---

## 📝 Required Format for Each Scenario File

Each file must export a single `scenario` object:

```javascript
export const scenario = {
  id: 'SCENARIO-ID-HERE',
  name: 'Descriptive Scenario Name',
  category: 'Vulnerability Category',
  cwe: 'CWE-Number',
  sink: 'dangerousFunctionName',
  guard: 'requiredGuardPattern',

  // 1. Original insecure code snippet
  vulnerableCode: `...`,

  // 2. Historical security fix that introduced the defensive guard
  fixedCode: `...`,

  // 3. Incoming Pull Request code being reviewed
  prCode: `...`,

  // 4. Expected analysis outcome
  expectedResult: 'PROVEN_REGRESSION', // or 'SAFE_PASS'
};
```

---

## 📊 Presentation Scorecard Target (Slide 4)

When all 6 scenarios are complete, running `node pitch-and-benchmark/benchmark-runner.js` will output:

| Metric | Target Score | Presentation Significance |
| :--- | :---: | :--- |
| **Regression Detection Rate** | **100% (4/4)** | Caught Guard Bypass, Removal, Sanitizer Swap & Inverse Patch |
| **False Alarm Rate** | **0.0% (0/2)** | Benign cleanups & route additions pass cleanly |
| **Analysis Latency** | **< 50ms** | Ultra-fast AST verification inside CI/CD |
