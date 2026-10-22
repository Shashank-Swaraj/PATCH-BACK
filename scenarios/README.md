# 🛡️ Security Scenarios & Testbed

**Assigned to:** Suhani (`feature/scenarios` branch)

## Your Task (Build from Scratch):
You need to research and write **3 code scenarios** in JavaScript/Node.js to test our detection tool.

Each scenario must show 3 stages of a real vulnerability:
1. **The Bug (Vulnerable Code):** An insecure function or endpoint.
2. **The Fix (Patched Code):** How developers fixed it by adding a defensive guard check.
3. **The Regression PR (Broken Refactor):** An innocent-looking pull request that accidentally removed or bypassed that guard!

---

## The 3 Files You Need to Create:

### 1. `01-path-traversal.js`
* **Vulnerability:** Path Traversal (Express `res.sendFile`).
* **The Bug:** `res.sendFile(req.query.file)` allows hackers to access `../../../../etc/passwd`.
* **The Fix:** Adds `if (!safePath.startsWith(root)) return 403;`.
* **The Regression PR:** A developer creates a helper function `sendAsset(res, path)` and a new route that calls it **without** the `startsWith` guard.

### 2. `02-command-injection.js`
* **Vulnerability:** Command Injection (`child_process.exec`).
* **The Bug:** `exec('ping ' + host)`.
* **The Fix:** Wrapping input in `shellEscape(host)`.
* **The Regression PR:** Someone refactors it using template literals `` `ping ${host}` `` and forgets `shellEscape`.

### 3. `03-benign-clean-pr.js`
* **Purpose:** A clean, safe PR (renaming a variable or adding comments) where the guard is **still present**.
* This proves our tool doesn't trigger false alarms on good code.

---

## Template to Follow:
Look at `template.js` in this folder for the exact structure to follow.
