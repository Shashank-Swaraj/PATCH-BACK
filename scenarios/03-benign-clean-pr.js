
/**
 * Scenario 03: Benign Clean PR
 *
 * OWASP Top 10:2025 — A01: Broken Access Control
 * CWE-22: Path Traversal
 *
 * Purpose:
 * Verify that PATCHBACK does not flag a harmless refactor
 * when the historical security guard remains in place.
 */

export const scenario = {
  id: 'SCENARIO-03-BENIGN-CLEAN-PR',
  name: 'Benign Refactor Preserves Path Guard',
  cwe: 'CWE-22',
  sink: 'res.sendFile',
  guard: 'safePath.startsWith(root + path.sep)',

  // Step 1: Original vulnerable code
  vulnerableCode: `
    app.get('/file', (req, res) => {
      res.sendFile(req.query.file);
    });
  `,

  // Step 2: Historical security fix
  fixedCode: `
    const path = require('path');
    const root = path.resolve(__dirname, 'public');

    app.get('/file', (req, res) => {
      const safePath = path.resolve(root, req.query.file);

      if (!safePath.startsWith(root + path.sep)) {
        return res.sendStatus(403);
      }

      res.sendFile(safePath);
    });
  `,

  // Step 3: Harmless refactor that preserves the guard
  prCode: `
    const path = require('path');
    const root = path.resolve(__dirname, 'public');

    app.get('/file', (req, res) => {
      const requestedFile = req.query.file;
      const safePath = path.resolve(root, requestedFile);

      if (!safePath.startsWith(root + path.sep)) {
        return res.sendStatus(403);
      }

      // Refactor: use a more descriptive variable name.
      const fileToSend = safePath;
      res.sendFile(fileToSend);
    });
  `,

  expectedResult: 'SAFE_PASS',
};
