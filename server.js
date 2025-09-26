// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// 可改到持久盘挂载点（如 Render Disk 挂载 /opt/data）
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const RESULTS_FILE = path.join(DATA_DIR, 'results.jsonl');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-env';
const TOKEN_COOKIE = 'token';

// === CORS：允许你的 GitHub Pages 访问（把下面用户名替换成你自己的）===
const ALLOWED_ORIGINS = [
  'https://sqgwang.github.io', // 不带仓库名
  // 如有自定义域名，在这里追加：'https://yourdomain.com'
];

app.set('trust proxy', 1);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: true
}));

// === helpers ===
function ensureDirs() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(RESULTS_FILE)) fs.writeFileSync(RESULTS_FILE, '', 'utf8');
  if (!fs.existsSync(USERS_FILE)) {
    const salt = bcrypt.genSaltSync(10);
    const password = Math.random().toString(36).slice(-10);
    const admin = {
      id: 'u_'+Date.now(),
      username: 'admin',
      passHash: bcrypt.hashSync(password, salt),
      role: 'admin',
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [admin] }, null, 2), 'utf8');
    console.log(`\n=== First run bootstrap ===
Admin account created:
  username: admin
  password: ${password}
Change it via POST /api/users or edit data/users.json
=====================================\n`);
  }
}
async function loadUsers() {
  const txt = await fsp.readFile(USERS_FILE, 'utf8');
  return JSON.parse(txt).users || [];
}
async function saveUsers(users) {
  await fsp.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
}
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function requireAuth(req, res, next) {
  try {
    const token = req.cookies[TOKEN_COOKIE];
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}
function genId(prefix='r') {
  const rand = Math.random().toString(36).slice(2,8);
  return `${prefix}_${Date.now()}_${rand}`;
}
async function appendResult(rec) {
  await fsp.appendFile(RESULTS_FILE, JSON.stringify(rec) + '\n', 'utf8');
}
async function readAllResults() {
  const txt = await fsp.readFile(RESULTS_FILE, 'utf8');
  if (!txt.trim()) return [];
  return txt.trim().split('\n').map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

// === middleware ===
ensureDirs();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

// === auth ===
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing credentials' });
  const users = await loadUsers();
  const u = users.find(x => x.username.toLowerCase() === String(username).toLowerCase());
  if (!u) return res.status(401).json({ error: 'invalid credentials' });
  const ok = bcrypt.compareSync(password, u.passHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = signToken({ sub: u.id, username: u.username, role: u.role });
  res.cookie(TOKEN_COOKIE, token, {
    httpOnly: true,
    sameSite: 'None', // 跨站必须 None
    secure: true,     // Render/HTTPS 必须 true
    maxAge: 7*24*3600*1000
  });
  res.json({ ok: true, user: { username: u.username, role: u.role } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(TOKEN_COOKIE, { sameSite: 'None', secure: true });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { username: req.user.username, role: req.user.role } });
});

// === users (admin) ===
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await loadUsers();
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt })));
});
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role='viewer' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });
  const users = await loadUsers();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'username exists' });
  }
  const salt = bcrypt.genSaltSync(10);
  const u = { id: genId('u'), username, passHash: bcrypt.hashSync(password, salt), role, createdAt: new Date().toISOString() };
  users.push(u);
  await saveUsers(users);
  res.json({ ok: true, id: u.id });
});
app.post('/api/users/reset', requireAuth, requireAdmin, async (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: 'missing fields' });
  const users = await loadUsers();
  const u = users.find(x => x.username.toLowerCase() === username.toLowerCase());
  if (!u) return res.status(404).json({ error: 'not found' });
  const salt = bcrypt.genSaltSync(10);
  u.passHash = bcrypt.hashSync(newPassword, salt);
  await saveUsers(users);
  res.json({ ok: true });
});

// === results ===
app.post('/api/results', async (req, res) => {
  const rec = req.body || {};
  if (!rec || !rec.trials || !Array.isArray(rec.trials)) {
    return res.status(400).json({ error: 'invalid payload' });
  }
  rec._id = genId('r');
  rec._ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  rec._ua = req.headers['user-agent'] || '';
  rec.createdAt = rec.createdAt || new Date().toISOString();
  await appendResult(rec);
  res.json({ ok: true, id: rec._id });
});

app.get('/api/results', requireAuth, async (req, res) => {
  const { limit=50, offset=0, search='' } = req.query;
  const all = await readAllResults();
  const q = String(search || '').trim().toLowerCase();
  const filtered = q ? all.filter(r => JSON.stringify(r).toLowerCase().includes(q)) : all;
  const start = Math.max(0, parseInt(offset,10)||0);
  const end = start + Math.min(500, parseInt(limit,10)||50);
  const slice = filtered.slice().reverse().slice(start, end);
  res.json({ total: filtered.length, items: slice });
});

app.get('/api/results/:id', requireAuth, async (req, res) => {
  const all = await readAllResults();
  const it = all.find(r => r._id === req.params.id);
  if (!it) return res.status(404).json({ error: 'not found' });
  res.json(it);
});

app.delete('/api/results/:id', requireAuth, requireAdmin, async (req, res) => {
  const all = await readAllResults();
  const next = all.filter(r => r._id !== req.params.id);
  if (next.length === all.length) return res.status(404).json({ error: 'not found' });
  const lines = next.map(r => JSON.stringify(r)).join('\n') + (next.length?'\n':'');
  await fsp.writeFile(RESULTS_FILE, lines, 'utf8');
  res.json({ ok: true });
});

// === start ===
app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});

