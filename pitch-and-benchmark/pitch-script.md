# 🎤 3-Minute Hackathon Pitch Script

**Owner:** Nikitah (`feature/pitch-benchmark` branch)

---

### [0:00 - 0:45] The Hook & Problem (Nikitah)
> "Good afternoon judges! In July 2024, the world was shocked by a vulnerability named **regreSSHion** in OpenSSH. 
> 
> What made it shocking was that the bug was originally discovered and fixed in **2006**. But in October 2020, an innocent code refactor accidentally removed the safety check. For **nearly four years**, millions of servers were left wide open to remote code execution because of a simple refactor.
> 
> Today, tools like Dependabot only look at package versions. CodeQL only flags known generic patterns. And human reviewers only see isolated diffs without historical context. Nobody remembers *why* that safety line was added."

---

### [0:45 - 1:30] The Solution & Innovation (Lead / You)
> "That’s why we built **PATCHBACK**—Security Regression Intelligence for open-source repositories.
> 
> PATCHBACK gives your codebase an institutional security memory. When a security patch is committed, PATCHBACK extracts the defense as a **Typed Security Invariant**—for example, *'Whenever sendFile is called, it must be guarded by startsWith(root)'*.
> 
> Crucially, our philosophy is: **'The LLM proposes the invariant, but deterministic code decides the PR verdict.'** We run pure AST static analysis in CI with zero hallucinations, catching regressions in under 10 milliseconds."

---

### [1:30 - 2:30] Live Demo & Scenarios (Sanjana & Suhani)
> **(Suhani):** "I built our real-world vulnerability testbed. Here is an Express file server where a 2022 patch added a path traversal guard. In PR #412, a junior developer extracted a helper function, creating a new route that skips the guard."
> 
> **(Sanjana):** "In our live dashboard, when the developer opens the PR, PATCHBACK immediately intercepts it. With one click, it proves the path from route to sink, identifies the missing guard on Line 3, and generates the exact GitHub Action comment blocking the merge."

---

### [2:30 - 3:00] Benchmark & Conclusion (Nikitah)
> "In our benchmark evaluation across seeded regressions and clean refactors, PATCHBACK achieved a **100% detection rate** with **0% false positives** on benign cleanups, taking just **4.2 milliseconds** per PR.
> 
> PATCHBACK: *Remember the fix. Protect the future.* Thank you, and we welcome your questions!"
