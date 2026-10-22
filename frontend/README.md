# 💻 Frontend & Interactive Dashboard (`frontend/`)

**Owner:** Sanjana (`feature/frontend` branch)

## What this module does:
This is the interactive visual presentation dashboard that the hackathon judges will see during our live demo. It lets users:
1. Select a security scenario (Path Traversal, Command Injection, Benign Cleanup).
2. Compare the historical security fix vs. the incoming refactoring PR.
3. Click **"Run PATCHBACK Invariant Check"** to simulate the scan live.
4. See the red alert banner, the broken line number, and copy the simulated GitHub Action comment!

## How to run the frontend on your laptop:
1. Open terminal inside the `frontend` folder:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
2. Open your browser at `http://localhost:5173`.
3. Feel free to tweak the UI, colors, layout, and styling!
