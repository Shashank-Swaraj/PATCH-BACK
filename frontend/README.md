# 💻 Frontend UI & Dashboard

**Assigned to:** Sanjana (`feature/frontend` branch)

## Your Task (Build from Scratch):
Build the interactive web dashboard that our team will show to the judges during our presentation.

### Requirements:
1. **Scenario Picker:** Let the user pick between test scenarios (e.g. Express Path Traversal, Command Injection, Clean PR).
2. **Code Display:** Show:
   - What the past security fix looked like (with the guard).
   - What the new Pull Request looks like (where the guard was removed or bypassed).
3. **Scan Button:** A big button: *"Run PATCHBACK Invariant Check"*.
4. **Alert / Verdict:**
   - If a regression is detected: Show a **Red Alert** with the broken line number and the missing guard.
   - If clean: Show a **Green Pass** badge.
   - A button to copy the simulated GitHub PR comment.

---

## How to Run & Work on Your Laptop:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. Edit `src/App.jsx` to build the UI!
