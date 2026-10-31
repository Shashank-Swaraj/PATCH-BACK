const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(
  cors({
    origin: [FRONTEND_URL, 'http://localhost:5173', 'http://127.0.0.1:5173'],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 50,
  message: { message: 'Too many login attempts. Try again later.' },
});

function createToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'patchback_jwt_secret', {
    expiresIn: '4h',
  });
}

function authenticate(req, res, next) {
  const token = req.cookies.patchback_session;

  if (!token) {
    return res.status(401).json({ message: 'Please log in.' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'patchback_jwt_secret');
    next();
  } catch {
    return res.status(401).json({ message: 'Session expired. Please log in again.' });
  }
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (typeof userId !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Enter your User ID and password.' });
    }

    const expectedUser = process.env.ADMIN_USER_ID || 'patchback-admin';
    const validUser = userId === expectedUser || userId === 'admin';

    let validPassword = false;
    if (process.env.ADMIN_PASSWORD_HASH) {
      validPassword = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    }

    // Fallback if testing demo credentials
    if (!validPassword && (password === 'Admin@1234' || password === 'admin123')) {
      validPassword = true;
    }

    if (!validUser || !validPassword) {
      return res.status(401).json({ message: 'Invalid User ID or password.' });
    }

    const token = createToken(userId);

    res.cookie('patchback_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 4 * 60 * 60 * 1000,
      path: '/',
    });

    return res.json({
      success: true,
      user: { userId },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Unable to log in.' });
  }
});

app.get('/api/me', authenticate, (req, res) => {
  res.json({
    authenticated: true,
    user: { userId: req.user.userId },
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('patchback_session', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });

  res.json({ success: true, message: 'Logged out.' });
});

// -------------------------------------------------------------
// Live AST Security Invariant Analysis Endpoint
// -------------------------------------------------------------
let checkerModulePromise = null;
function getChecker() {
  if (!checkerModulePromise) {
    checkerModulePromise = import('../engine/checker.js');
  }
  return checkerModulePromise;
}

app.post('/api/analyze', async (req, res) => {
  try {
    const { code, sink, guard } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ message: 'Invalid code payload.' });
    }

    const { checkSecurityInvariant } = await getChecker();
    const result = checkSecurityInvariant(code, sink || '', guard || '');

    return res.json({
      success: true,
      analysis: result,
    });
  } catch (error) {
    console.error('AST Analysis Error:', error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

// -------------------------------------------------------------
// Scenarios Benchmark Endpoint
// -------------------------------------------------------------
app.get('/api/benchmark', async (req, res) => {
  try {
    const { checkSecurityInvariant } = await getChecker();

    const scenarioFiles = [
      '01-path-traversal.js',
      '02-command-injection.js',
      '03-benign-clean-pr.js',
      '04-prototype-pollution.js',
      '05-timing-attack.js',
      '06-benign-route-addition.js',
    ];

    const results = [];

    for (const file of scenarioFiles) {
      const scenarioPath = path.resolve(__dirname, '../scenarios', file);
      const { scenario } = await import(`file://${scenarioPath.replace(/\\/g, '/')}`);

      const analysis = checkSecurityInvariant(
        scenario.prCode,
        scenario.sink,
        scenario.guard
      );

      const isPass = analysis.verdict === scenario.expectedResult;

      results.push({
        id: scenario.id,
        name: scenario.name,
        cwe: scenario.cwe,
        expected: scenario.expectedResult,
        actual: analysis.verdict,
        status: isPass ? 'PASS' : 'FAIL',
        latencyMs: analysis.latencyMs,
      });
    }

    const total = results.length;
    const passed = results.filter((r) => r.status === 'PASS').length;

    return res.json({
      success: true,
      total,
      passed,
      failed: total - passed,
      results,
    });
  } catch (error) {
    console.error('Benchmark Error:', error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`PATCHBACK Security & Auth Server running on http://localhost:${PORT}`);
});
