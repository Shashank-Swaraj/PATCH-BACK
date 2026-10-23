
/**
 * Scenario 01: Path Traversal Regression
 *
 * OWASP Top 10:2025 — A01: Broken Access Control
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 *
 * Purpose:
 * Verify that PATCHBACK detects a refactor that removes the
 * path-containment guard introduced by a historical security fix.
 */

export const scenario = {
  id: 'SCENARIO-01-PATH-TRAVERSAL',
  name: 'Express Path Traversal Regression',
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
    const path = require('node:path');
    const root = path.resolve(__dirname, 'public');

    app.get('/file', (req, res) => {
      const requestedFile = String(req.query.file ?? '');
      const safePath = path.resolve(root, requestedFile);
      const relativePath = path.relative(root, safePath);

      const isInsideRoot =
        relativePath === '' ||
        (
          relativePath !== '..' &&
          !relativePath.startsWith('..' + path.sep) &&
          !path.isAbsolute(relativePath)
        );

      if (!isInsideRoot) {
        return res.sendStatus(403);
      }

      return res.sendFile(safePath);
    });
  `,

  // Step 3: Regression PR removes the historical guard
  prCode: `
    const path = require('node:path');
    const root = path.resolve(__dirname, 'public');

    function sendAsset(res, filePath) {
      return res.sendFile(filePath);
    }

    app.get('/file', (req, res) => {
      const requestedFile = String(req.query.file ?? '');
      const safePath = path.resolve(root, requestedFile);

      // Regression: path-containment validation is missing.
      return sendAsset(res, safePath);
    });
  `,

  expectedResult: 'PROVEN_REGRESSION',
};
