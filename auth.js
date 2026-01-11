const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cookieParser = require('cookie-parser');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cookieParser());

// CORS: allow credentials and specific origins. Set AUTH_ORIGINS env to a comma-separated
// list of allowed origins in production (e.g. https://thaovystore.netlify.app)
const allowedOrigins = process.env.AUTH_ORIGINS ? process.env.AUTH_ORIGINS.split(',') : ['http://localhost:3000', 'http://localhost:4000', 'http://localhost:4001', 'http://localhost:4002', 'http://localhost'];
app.use(cors({ origin: function(origin, cb) {
  // allow requests with no origin (e.g. curl, mobile)
  if (!origin) return cb(null, true);
  if (allowedOrigins.indexOf(origin) !== -1) return cb(null, true);
  return cb(new Error('CORS not allowed'), false);
}, credentials: true }));

// Helper to build cookie options depending on environment
function cookieOptions() {
  const isProd = process.env.NODE_ENV === 'production' || (process.env.COOKIE_SECURE === 'true');
  // For cross-site cookies, browsers require `SameSite=None` and `Secure`.
  // Use `Lax`/non-secure when testing on localhost over http.
  const sameSite = process.env.COOKIE_SAMESITE || (isProd ? 'None' : 'Lax');
  return { httpOnly: true, sameSite, secure: isProd, path: '/', maxAge: 30 * 24 * 60 * 60 * 1000 };
}

const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_secret';
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES || '15m';

function loadSessions() {
  try {
    const s = fs.readFileSync(SESSIONS_FILE, 'utf8');
    return JSON.parse(s || '{}');
  } catch (e) {
    return {};
  }
}

function saveSessions(sessions) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2), 'utf8');
}

function createAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

// Demo users - replace with real user DB/auth in production
const demoUsers = {
  "user1": "password",
  "admin": "adminpass"
};

app.post('/api/login', (req, res) => {
  const { username, password, deviceName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  // Simple demo auth - replace with real verification
  if (!demoUsers[username] || demoUsers[username] !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const sessions = loadSessions();
  const sessionId = crypto.randomUUID();
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const createdAt = new Date().toISOString();

  const session = { sessionId, deviceName: deviceName || 'unknown', refreshToken, createdAt };
  sessions[username] = sessions[username] || [];
  sessions[username].push(session);
  saveSessions(sessions);

  const accessToken = createAccessToken({ username, sessionId });
  // Set refresh token as HttpOnly cookie so client cannot read it via JS
  res.cookie('refreshToken', refreshToken, cookieOptions());
  return res.json({ accessToken, sessionId, expiresIn: ACCESS_EXPIRES });
});

app.post('/api/refresh', (req, res) => {
  // Try cookie first, then body
  const tokenFromBody = (req.body && req.body.refreshToken) || null;
  const refreshToken = tokenFromBody || req.cookies && req.cookies.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });

  const sessions = loadSessions();
  for (const username of Object.keys(sessions)) {
    const userSessions = sessions[username] || [];
    const found = userSessions.find(s => s.refreshToken === refreshToken);
    if (found) {
      const accessToken = createAccessToken({ username, sessionId: found.sessionId });
      return res.json({ accessToken, expiresIn: ACCESS_EXPIRES });
    }
  }
  return res.status(401).json({ error: 'Invalid refresh token' });
});

app.post('/api/logout', (req, res) => {
  const { refreshToken: bodyRefreshToken, sessionId, username } = req.body || {};
  const cookieRefresh = req.cookies && req.cookies.refreshToken;
  const refreshToken = bodyRefreshToken || cookieRefresh;
  if (!refreshToken && (!sessionId || !username)) return res.status(400).json({ error: 'Provide refreshToken OR username+sessionId' });

  const sessions = loadSessions();
  if (refreshToken) {
    for (const user of Object.keys(sessions)) {
      const before = sessions[user].length;
      sessions[user] = sessions[user].filter(s => s.refreshToken !== refreshToken);
      if (sessions[user].length === 0) delete sessions[user];
      if (sessions[user] && sessions[user].length !== before) {
        saveSessions(sessions);
        // clear cookie
        try { res.clearCookie('refreshToken', cookieOptions()); } catch (e) {}
        return res.json({ ok: true });
      }
    }
    return res.status(404).json({ error: 'Session not found' });
  }

  // username + sessionId invalidation
  if (sessions[username]) {
    const before = sessions[username].length;
    sessions[username] = sessions[username].filter(s => s.sessionId !== sessionId);
    if (sessions[username].length === 0) delete sessions[username];
    if (sessions[username] && sessions[username].length !== before) {
      saveSessions(sessions);
      try { res.clearCookie('refreshToken', { path: '/' }); } catch (e) {}
      return res.json({ ok: true });
    }
  }
  saveSessions(sessions);
  return res.status(404).json({ error: 'Session not found' });
});

app.get('/api/sessions', (req, res) => {
  const { username } = req.query || {};
  const sessions = loadSessions();
  if (!username) return res.json(sessions);
  const userSessions = sessions[username] || [];
  // mask refresh tokens in listing
  const safe = userSessions.map(s => ({ sessionId: s.sessionId, deviceName: s.deviceName, createdAt: s.createdAt }));
  return res.json(safe);
});

function authenticateMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = auth.substring(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.get('/api/protected', authenticateMiddleware, (req, res) => {
  res.json({ ok: true, user: req.user });
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`Auth server listening on ${PORT}`));
