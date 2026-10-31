
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { message: 'Too many login attempts. Try again later.' },
});

function createToken(userId) {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function authenticate(req, res, next) {
  const token = req.cookies.patchback_session;

  if (!token) {
    return res.status(401).json({ message: 'Please log in.' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Session expired. Please log in again.' });
  }
}

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (typeof userId !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Enter your User ID and password.' });
    }

    const validUser = userId === process.env.ADMIN_USER_ID;
    const validPassword = await bcrypt.compare(
      password,
      process.env.ADMIN_PASSWORD_HASH
    );

    if (!validUser || !validPassword) {
      return res.status(401).json({ message: 'Invalid User ID or password.' });
    }

    const token = createToken(userId);

    res.cookie('patchback_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000,
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
    sameSite: 'strict',
    path: '/',
  });

  res.json({ success: true, message: 'Logged out.' });
});

app.listen(PORT, () => {
  console.log(`PATCHBACK authentication server running on http://localhost:${PORT}`);
});
