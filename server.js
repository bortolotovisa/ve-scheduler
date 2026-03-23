const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const CAPACITY_FILE = path.join(DATA_DIR, 'capacity.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ── INIT DEFAULTS ─────────────────────────────────────────────────────────────
if (!fs.existsSync(USERS_FILE)) {
  writeJSON(USERS_FILE, [
    { id: '1', name: 'Juliana', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-0', role: 'manager' },
    { id: '2', name: 'Programmer 2', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-1', role: 'programmer' },
    { id: '3', name: 'Viewer', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-2', role: 'viewer' },
    { id: '4', name: 'Project Manager', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-3', role: 'projectmanager' }
  ]);
}
if (!fs.existsSync(PROJECTS_FILE)) writeJSON(PROJECTS_FILE, []);
if (!fs.existsSync(SESSIONS_FILE)) writeJSON(SESSIONS_FILE, {});
if (!fs.existsSync(CAPACITY_FILE)) writeJSON(CAPACITY_FILE, {});

// ── SESSIONS ──────────────────────────────────────────────────────────────────
const SESSION_TTL = 8 * 60 * 60 * 1000;

function createSession(user) {
  const sessions = readJSON(SESSIONS_FILE, {});
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  // Clean expired
  Object.keys(sessions).forEach(k => { if (now - sessions[k].created > SESSION_TTL) delete sessions[k]; });
  sessions[token] = { userId: user.id, name: user.name, role: user.role, color: user.color, created: now };
  writeJSON(SESSIONS_FILE, sessions);
  return token;
}

function getSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) return null;
  const sessions = readJSON(SESSIONS_FILE, {});
  const s = sessions[token];
  if (!s || Date.now() - s.created > SESSION_TTL) {
    if (s) { delete sessions[token]; writeJSON(SESSIONS_FILE, sessions); }
    return null;
  }
  return s;
}

function requireAuth(...roles) {
  return (req, res, next) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'Not authenticated' });
    if (roles.length && !roles.includes(s.role)) return res.status(403).json({ error: 'Access denied' });
    req.session = s;
    next();
  };
}

function calcTimeSpent(log) {
  let total = 0, start = null;
  for (const e of (log || [])) {
    if (e.action === 'started' || e.action === 'resumed') start = e.ts;
    if ((e.action === 'paused' || e.action === 'done' || e.action === 'reopened') && start) {
      total += e.ts - start; start = null;
    }
  }
  return total;
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { name, password } = req.body;
  const user = readJSON(USERS_FILE, []).find(u => u.name === name);
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  if (user.mustChange)
    return res.json({ mustChange: true, name: user.name, color: user.color, role: user.role, tabs: user.tabs });
  const token = createSession(user);
  res.json({ token, name: user.name, color: user.color, role: user.role, tabs: user.tabs });
});

app.post('/api/auth/set-password', (req, res) => {
  const { name, currentPassword, newPassword } = req.body;
  const users = readJSON(USERS_FILE, []);
  const user = users.find(u => u.name === name);
  if (!user || !bcrypt.compareSync(currentPassword, user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  user.passwordHash = bcrypt.hashSync(newPassword, 8);
  user.mustChange = false;
  writeJSON(USERS_FILE, users);
  const token = createSession(user);
  res.json({ token, name: user.name, color: user.color, role: user.role, tabs: user.tabs });
});

// Reset all project data — manager only
app.delete('/api/projects/all', requireAuth('manager'), (req, res) => {
  writeJSON(PROJECTS_FILE, []);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) {
    const sessions = readJSON(SESSIONS_FILE, {});
    delete sessions[token];
    writeJSON(SESSIONS_FILE, sessions);
  }
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ name: s.name, color: s.color, role: s.role });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
  const users = readJSON(USERS_FILE, []);
  res.json(users.map(u => ({ id: u.id, name: u.name, color: u.color, role: u.role })));
});

app.post('/api/users', requireAuth('manager'), (req, res) => {
  const { users } = req.body;
  const existing = readJSON(USERS_FILE, []);
  const updated = users.map((u, i) => {
    const prev = existing.find(e => e.name === u.name || e.id === u.id);
    return {
      id: prev?.id || String(Date.now() + i),
      name: u.name, color: u.color || `prog-${i}`, role: u.role || 'programmer',
      passwordHash: u.password ? bcrypt.hashSync(u.password, 8) : (prev?.passwordHash || bcrypt.hashSync('ve2026', 8))
    };
  });
  writeJSON(USERS_FILE, updated);
  res.json({ ok: true });
});

// ── PROJECTS ──────────────────────────────────────────────────────────────────
app.get('/api/projects', (req, res) => {
  res.json(readJSON(PROJECTS_FILE, []));
});

app.post('/api/projects', requireAuth('manager', 'projectmanager'), (req, res) => {
  writeJSON(PROJECTS_FILE, req.body.projects);
  res.json({ ok: true });
});

app.patch('/api/projects/:pid/duedate', requireAuth('manager', 'projectmanager'), (req, res) => {
  const projects = readJSON(PROJECTS_FILE, []);
  const p = projects.find(x => x.id === req.params.pid);
  if (!p) return res.status(404).json({ error: 'Not found' });
  if (!p.dateHistory) p.dateHistory = [];
  p.dateHistory.push({ from: p.dueStr, to: req.body.dueStr, changedAt: Date.now(), changedBy: req.session.name });
  p.dueStr = req.body.dueStr;
  p.dueDate = req.body.dueDate;
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// ── BATCH UPDATE ──────────────────────────────────────────────────────────────
app.post('/api/batch', requireAuth('manager', 'programmer', 'projectmanager'), (req, res) => {
  const { updates } = req.body;
  const s = req.session;
  const projects = readJSON(PROJECTS_FILE, []);

  for (const u of updates) {
    const proj = projects.find(p => p.id === u.pid);
    if (!proj) continue;
    const part = proj.parts.find(pt => pt.id === u.partId);
    if (!part) continue;
    // Programmers only update own parts
    if (s.role === 'programmer' && part.assignedTo !== s.name) continue;
    if (u.status !== undefined) part.status = u.status;
    if (u.assignedTo !== undefined) part.assignedTo = u.assignedTo || null;
    if (u.notes !== undefined) part.notes = u.notes;
    if (u.log) { if (!part.log) part.log = []; part.log.push({ ...u.log, user: s.name }); }
  }

  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// ── CAPACITY ──────────────────────────────────────────────────────────────────
app.get('/api/capacity', requireAuth('manager'), (req, res) => {
  res.json(readJSON(CAPACITY_FILE, {}));
});

app.post('/api/capacity', requireAuth('manager'), (req, res) => {
  const cap = readJSON(CAPACITY_FILE, {});
  cap[req.body.week] = req.body.capacities;
  writeJSON(CAPACITY_FILE, cap);
  res.json({ ok: true });
});

// ── ANALYTICS ─────────────────────────────────────────────────────────────────
app.get('/api/analytics', requireAuth('manager'), (req, res) => {
  const projects = readJSON(PROJECTS_FILE, []);
  const allParts = projects.flatMap(p => p.parts.map(pt => ({
    ...pt, projectName: p.projectName, client: p.client, dueDate: p.dueDate, dueStr: p.dueStr
  })));

  // By person stats
  const byPerson = {};
  allParts.forEach(pt => {
    if (!pt.assignedTo) return;
    if (!byPerson[pt.assignedTo]) byPerson[pt.assignedTo] = { done: 0, inprogress: 0, paused: 0, drawing: 0, nowo: 0, totalTime: 0, pauses: 0, revisions: 0 };
    byPerson[pt.assignedTo][pt.status] = (byPerson[pt.assignedTo][pt.status] || 0) + 1;
    if (pt.log) {
      byPerson[pt.assignedTo].pauses += pt.log.filter(e => e.action === 'paused').length;
      byPerson[pt.assignedTo].revisions += pt.log.filter(e => e.action === 'reopened').length;
      byPerson[pt.assignedTo].totalTime += calcTimeSpent(pt.log);
    }
  });

  // Date change history
  const dateChanges = projects
    .filter(p => p.dateHistory?.length)
    .map(p => ({ projectName: p.projectName, client: p.client, changes: p.dateHistory.length, history: p.dateHistory }))
    .sort((a, b) => b.changes - a.changes);

  // Pause reasons
  const pauseReasons = {};
  allParts.forEach(pt => {
    (pt.log || []).filter(e => e.action === 'paused' && e.reason).forEach(e => {
      pauseReasons[e.reason] = (pauseReasons[e.reason] || 0) + 1;
    });
  });

  // Outside nearing deadline
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const outsideAlert = projects.flatMap(p =>
    p.parts.filter(pt => pt.status === 'outside').map(pt => {
      const due = p.dueDate ? new Date(p.dueDate) : null;
      due?.setHours(0, 0, 0, 0);
      const daysLeft = due ? Math.ceil((due - now) / 86400000) : null;
      return { ...pt, projectName: p.projectName, client: p.client, dueStr: p.dueStr, daysLeft };
    })
  ).filter(pt => pt.daysLeft !== null && pt.daysLeft <= 7).sort((a, b) => a.daysLeft - b.daysLeft);

  // Parts done per day (last 30 days)
  const doneByDay = {};
  allParts.forEach(pt => {
    (pt.log || []).filter(e => e.action === 'done').forEach(e => {
      const day = new Date(e.ts).toLocaleDateString('en-CA');
      if (!doneByDay[day]) doneByDay[day] = {};
      doneByDay[day][pt.assignedTo || 'unassigned'] = (doneByDay[day][pt.assignedTo || 'unassigned'] || 0) + 1;
    });
  });

  res.json({ byPerson, dateChanges, pauseReasons, outsideAlert, doneByDay });
});

// ── DAILY SUMMARY (public) ────────────────────────────────────────────────────
app.get('/api/summary', (req, res) => {
  const projects = readJSON(PROJECTS_FILE, []);
  const allParts = projects.flatMap(p => p.parts.map(pt => ({ ...pt, dueDate: p.dueDate })));
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const weekEnd = new Date(now); weekEnd.setDate(weekEnd.getDate() + 7);

  const overdue = projects.filter(p => {
    if (!p.dueDate) return false;
    const d = new Date(p.dueDate); d.setHours(0, 0, 0, 0);
    return d < now && !p.parts.every(pt => ['done','outside'].includes(pt.status));
  }).length;

  const thisWeek = projects.filter(p => {
    if (!p.dueDate) return false;
    const d = new Date(p.dueDate); d.setHours(0, 0, 0, 0);
    return d >= now && d <= weekEnd;
  }).length;

  const workload = {};
  allParts.filter(pt => pt.assignedTo && !['done','outside'].includes(pt.status)).forEach(pt => {
    if (!workload[pt.assignedTo]) workload[pt.assignedTo] = { total: 0, thisWeek: 0, inprogress: 0 };
    workload[pt.assignedTo].total++;
    if (pt.dueDate) {
      const d = new Date(pt.dueDate); d.setHours(0, 0, 0, 0);
      if (d >= now && d <= weekEnd) workload[pt.assignedTo].thisWeek++;
    }
    if (pt.status === 'inprogress') workload[pt.assignedTo].inprogress++;
  });

  res.json({
    overdue, thisWeek,
    noWo: allParts.filter(pt => pt.status === 'nowo').length,
    needsAction: allParts.filter(pt => pt.status === 'drawing').length,
    workload,
    date: new Date().toLocaleDateString('en-CA', { weekday: 'long', month: 'long', day: 'numeric' })
  });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`VE Scheduler on port ${PORT}`));
