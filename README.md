# 🛡️ PATCHBACK

> **Security Regression Intelligence for Open-Source Packages**  
> *"Remember the fix. Protect the future."*  
> **AVISHKAR FET Hackathon • Jain (Deemed-to-be University)**

---

## 👥 The Team & Folder Assignments

| Member | Role | Assigned Folder | Your Branch Name |
| :--- | :--- | :--- | :--- |
| **Lead (You)** | Core Engine & AST Analyzer | `engine/` | `main` |
| **Suhani** | Security Testbed & CVE Scenarios | `scenarios/` | `feature/scenarios` |
| **Sanjana** | Frontend & Interactive UI | `frontend/` | `feature/frontend` |
| **Nikitah** | Integration, Benchmark & Pitch | `pitch-and-benchmark/` | `feature/pitch-benchmark` |

---

## 🚀 How to Get Started (For Suhani, Sanjana & Nikitah)

### Step 1: Clone the repository to your laptop
```bash
git clone <GITHUB-REPO-URL>
cd AVISHKAR
```

### Step 2: Create and switch to your feature branch
* **If you are Suhani:**
  ```bash
  git checkout -b feature/scenarios
  ```
* **If you are Sanjana:**
  ```bash
  git checkout -b feature/frontend
  ```
* **If you are Nikitah:**
  ```bash
  git checkout -b feature/pitch-benchmark
  ```

### Step 3: Install dependencies & work in your folder
* Go to your folder and follow the instructions in your folder's `README.md`.

### Step 4: Push your work and open a Pull Request (PR)
```bash
git add .
git commit -m "feat: completed my module"
git push origin <your-branch-name>
```
Then go to GitHub and click **"Compare & pull request"**.

---

## 🧠 What is PATCHBACK in 30 Seconds?

* **The Problem:** When an open-source project fixes a security bug, another developer often rewrites or cleans up the code 2 years later and **accidentally deletes or forgets the security check**. Tools like Dependabot miss this completely because Dependabot only checks version numbers in `package.json`, not code logic.
* **Our Solution:** PATCHBACK acts as the repository's security memory. It extracts past security fixes as **rules**, and deterministically scans every new Pull Request to ensure defensive checks are never removed or bypassed.
* **Core Principle:** *"The LLM proposes the rule, but code strictly decides the PR verdict."*

---

## 📁 Repository Structure Overview

```
AVISHKAR/
├── engine/                 # 👤 Lead: AST parser & guard reachability checker
├── scenarios/              # 👤 Suhani: Vulnerable, patched, and broken PR test fixtures
├── frontend/               # 👤 Sanjana: React + Vite web dashboard for the demo
└── pitch-and-benchmark/    # 👤 Nikitah: Presentation slides, script & benchmark scorecard
```
