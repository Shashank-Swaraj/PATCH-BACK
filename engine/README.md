# ⚙️ Core Engine Module (`engine/`)

**Owner:** Lead (You)

## What this module does:
This is the heart of **PATCHBACK**. It parses JavaScript code into an Abstract Syntax Tree (AST) using `@babel/parser` and verifies whether sensitive APIs (sinks like `sendFile`, `exec`) are always guarded by their required security conditions (guards like `startsWith`, `shellEscape`).

## How to test:
1. Install Babel dependencies:
   ```bash
   cd engine
   npm install
   ```
2. Run the test script:
   ```bash
   node test-demo.js
   ```

You will see the engine parse the PR, locate line 9 (`res.sendFile`), detect that `startsWith` is missing in `sendAsset`, and print the `PROVEN_REGRESSION` alert in under 10 milliseconds.
