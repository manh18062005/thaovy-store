const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
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
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_secret';
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES || '15m';

function loadSessions() {
  try {
    const s = fs.readFileSync(SESSIONS_FILE, 'utf8');
    const raw = JSON.parse(s || '{}');
    // Migrate old format where sessions[username] was an array -> new format: { sessions: [], profile: {} }
    let migrated = false;
    Object.keys(raw).forEach(k => {
      if (Array.isArray(raw[k])) {
        raw[k] = { sessions: raw[k], profile: { username: k, email: k } };
        migrated = true;
      }
    });
    if (migrated) {
      try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(raw, null, 2), 'utf8'); console.log('Migrated sessions.json to new object shape'); } catch (e) { console.log('Migration write failed', e && e.message); }
    }
    return raw;
  } catch (e) {
    return {};
  }
}

function saveSessions(sessions) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2), 'utf8');
}

function loadUsers() {
  try {
    const u = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(u || '{}');
  } catch (e) {
    return {};
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function createAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

// Demo users - replace with real user DB/auth in production
const demoUsers = {
  "user1": "password",
  "admin": "adminpass",
  "nhatquan1@gmail.com": "password"
};

// Pre-hash demo users' passwords so we store/compare hashed passwords everywhere
const demoUsersHashed = {};
Object.keys(demoUsers).forEach(k => {
  demoUsersHashed[k] = bcrypt.hashSync(demoUsers[k], 10);
});

// Get all users (merged from demoUsersHashed + registered users in users.json)
function getAllUsers() {
  const registeredUsers = loadUsers();
  // registeredUsers should already contain hashed passwords
  return { ...demoUsersHashed, ...registeredUsers };
}

app.post('/api/login', async (req, res) => {
  const { username, password, deviceName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  // Verify hashed password
  const allUsers = getAllUsers();
  const storedHash = allUsers[username];
  if (!storedHash) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, storedHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const sessions = loadSessions();
  const sessionId = crypto.randomUUID();
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const createdAt = new Date().toISOString();

  const session = { sessionId, deviceName: deviceName || 'unknown', refreshToken, createdAt };
  sessions[username] = sessions[username] || { sessions: [], profile: {} };
  if (!Array.isArray(sessions[username].sessions)) sessions[username].sessions = [];
  sessions[username].sessions.push(session);
  // Initialize profile if not exists
  if (!sessions[username].profile) sessions[username].profile = {};
  sessions[username].profile.username = username;
  sessions[username].profile.fullName = sessions[username].profile.fullName || '';
  sessions[username].profile.email = username;
  saveSessions(sessions);

  const accessToken = createAccessToken({ username, sessionId });
  // Set refresh token as HttpOnly cookie so client cannot read it via JS
  res.cookie('refreshToken', refreshToken, cookieOptions());
  return res.json({ accessToken, sessionId, expiresIn: ACCESS_EXPIRES, user: sessions[username].profile });
});

app.post('/api/refresh', (req, res) => {
  // Try cookie first, then body
  const tokenFromBody = (req.body && req.body.refreshToken) || null;
  const refreshToken = tokenFromBody || req.cookies && req.cookies.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });

  const sessions = loadSessions();
  for (const username of Object.keys(sessions)) {
    const entry = sessions[username] || { sessions: [], profile: {} };
    const userSessions = entry.sessions || [];
    const found = userSessions.find(s => s.refreshToken === refreshToken);
    if (found) {
      const userProfile = entry.profile || { username, email: username };
      const accessToken = createAccessToken({ username, sessionId: found.sessionId });
      return res.json({ accessToken, expiresIn: ACCESS_EXPIRES, user: userProfile });
    }
  }
  return res.status(401).json({ error: 'Invalid refresh token' });
});

app.post('/api/register', async (req, res) => {
  const { username, password, fullName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const allUsers = getAllUsers();
  if (allUsers[username]) return res.status(409).json({ error: 'Username already exists' });

  // Hash password before saving
  const hashed = await bcrypt.hash(password, 10);
  const registeredUsers = loadUsers();
  registeredUsers[username] = hashed;
  saveUsers(registeredUsers);

  // Also initialize empty sessions/profile structure if not present
  const sessions = loadSessions();
  if (!sessions[username]) sessions[username] = { sessions: [], profile: { username, email: username, fullName: fullName || '' } };
  if (!sessions[username].profile) sessions[username].profile = { username, email: username, fullName: fullName || '' };
  if (fullName) sessions[username].profile.fullName = fullName;
  saveSessions(sessions);

  return res.json({ ok: true, message: 'User registered successfully' });
});

app.post('/api/logout', (req, res) => {
  const { refreshToken: bodyRefreshToken, sessionId, username } = req.body || {};
  const cookieRefresh = req.cookies && req.cookies.refreshToken;
  const refreshToken = bodyRefreshToken || cookieRefresh;
  if (!refreshToken && (!sessionId || !username)) return res.status(400).json({ error: 'Provide refreshToken OR username+sessionId' });

  const sessions = loadSessions();
  if (refreshToken) {
    for (const user of Object.keys(sessions)) {
      const entry = sessions[user] || { sessions: [], profile: {} };
      const before = (entry.sessions || []).length;
      entry.sessions = (entry.sessions || []).filter(s => s.refreshToken !== refreshToken);
      // remove user entirely only when no sessions and profile empty
      if ((entry.sessions || []).length === 0 && (!entry.profile || Object.keys(entry.profile).length === 0)) {
        delete sessions[user];
      } else {
        sessions[user] = entry;
      }
      if ((entry.sessions || []).length !== before) {
        saveSessions(sessions);
        try { res.clearCookie('refreshToken', cookieOptions()); } catch (e) {}
        return res.json({ ok: true });
      }
    }
    return res.status(404).json({ error: 'Session not found' });
  }
  // username + sessionId invalidation
  if (sessions[username]) {
    const entry = sessions[username] || { sessions: [], profile: {} };
    const before = (entry.sessions || []).length;
    entry.sessions = (entry.sessions || []).filter(s => s.sessionId !== sessionId);
    if ((entry.sessions || []).length === 0 && (!entry.profile || Object.keys(entry.profile).length === 0)) {
      delete sessions[username];
    } else {
      sessions[username] = entry;
    }
    if ((entry.sessions || []).length !== before) {
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
  const entry = sessions[username] || { sessions: [] };
  const userSessions = entry.sessions || [];
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

// Get current user info from JWT
app.get('/api/me', authenticateMiddleware, (req, res) => {
  const { username } = req.user;
  const sessions = loadSessions();
  const userProfile = sessions[username]?.profile || { username, email: username };
  return res.json(userProfile);
});

// Update user profile
app.post('/api/profile', authenticateMiddleware, (req, res) => {
  const { username } = req.user;
  const { fullName, gender, birthday, address, bankName, bankNumber, avatar } = req.body || {};
  
  const sessions = loadSessions();
  if (!sessions[username]) {
    sessions[username] = { sessions: [], profile: { username, email: username } };
  }
  if (!sessions[username].profile) sessions[username].profile = {};
  
  // Update fields if provided
  if (fullName !== undefined) sessions[username].profile.fullName = fullName;
  if (gender !== undefined) sessions[username].profile.gender = gender;
  if (birthday !== undefined) sessions[username].profile.birthday = birthday;
  if (address !== undefined) sessions[username].profile.address = address;
  if (bankName !== undefined) sessions[username].profile.bankName = bankName;
  if (bankNumber !== undefined) sessions[username].profile.bankNumber = bankNumber;
  if (avatar !== undefined) sessions[username].profile.avatar = avatar;
  
  saveSessions(sessions);
  return res.json({ ok: true, profile: sessions[username].profile });
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`Auth server listening on ${PORT}`));
