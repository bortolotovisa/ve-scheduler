const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// ── INIT DATA DIR ─────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Init default users if none exist
if (!fs.existsSync(USERS_FILE)) {
  writeJSON(USERS_FILE, [
    { id: '1', name: 'Juliana', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-0', role: 'manager' },
    { id: '2', name: 'Programmer 2', passwordHash: bcrypt.hashSync('ve2026', 8), color: 'prog-1', role: 'programmer' }
  ]);
}
if (!fs.existsSync(PROJECTS_FILE)) writeJSON(PROJECTS_FILE, []);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── API: AUTH ─────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { name, password } = req.body;
  const users = readJSON(USERS_FILE, []);
  const user = users.find(u => u.name === name);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ name: user.name, color: user.color, role: user.role });
});

// ── API: USERS ────────────────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
  const users = readJSON(USERS_FILE, []);
  res.json(users.map(u => ({ id: u.id, name: u.name, color: u.color, role: u.role })));
});

app.post('/api/users', (req, res) => {
  const { users } = req.body;
  const existing = readJSON(USERS_FILE, []);
  const updated = users.map((u, i) => {
    const prev = existing.find(e => e.name === u.name);
    return {
      id: prev?.id || String(Date.now() + i),
      name: u.name,
      color: u.color || `prog-${i}`,
      role: u.role || 'programmer',
      passwordHash: u.password
        ? bcrypt.hashSync(u.password, 8)
        : (prev?.passwordHash || bcrypt.hashSync('ve2026', 8))
    };
  });
  writeJSON(USERS_FILE, updated);
  res.json({ ok: true });
});

// ── API: PROJECTS ─────────────────────────────────────────────────────────────
app.get('/api/projects', (req, res) => {
  res.json(readJSON(PROJECTS_FILE, []));
});

// Full replace after CSV import (smart merge done client-side)
app.post('/api/projects', (req, res) => {
  const { projects } = req.body;
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true, count: projects.length });
});

// Update single part status
app.patch('/api/parts/:partId/status', (req, res) => {
  const { partId } = req.params;
  const { status, pid } = req.body;
  const projects = readJSON(PROJECTS_FILE, []);
  const project = projects.find(p => p.id === pid);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const part = project.parts.find(pt => pt.id === partId);
  if (!part) return res.status(404).json({ error: 'Part not found' });
  part.status = status;
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// Update single part assignment
app.patch('/api/parts/:partId/assign', (req, res) => {
  const { partId } = req.params;
  const { assignedTo, pid } = req.body;
  const projects = readJSON(PROJECTS_FILE, []);
  const project = projects.find(p => p.id === pid);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const part = project.parts.find(pt => pt.id === partId);
  if (!part) return res.status(404).json({ error: 'Part not found' });
  part.assignedTo = assignedTo || null;
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// Add log event to part
app.post('/api/parts/:partId/log', (req, res) => {
  const { partId } = req.params;
  const { pid, event } = req.body;
  const projects = readJSON(PROJECTS_FILE, []);
  const project = projects.find(p => p.id === pid);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const part = project.parts.find(pt => pt.id === partId);
  if (!part) return res.status(404).json({ error: 'Part not found' });
  if (!part.log) part.log = [];
  part.log.push(event);
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// Batch update (for pause+start-next in one call)
app.post('/api/batch', (req, res) => {
  const { updates } = req.body; // [{pid, partId, status, log?}]
  const projects = readJSON(PROJECTS_FILE, []);
  for (const u of updates) {
    const project = projects.find(p => p.id === u.pid);
    if (!project) continue;
    const part = project.parts.find(pt => pt.id === u.partId);
    if (!part) continue;
    if (u.status) part.status = u.status;
    if (u.log) { if (!part.log) part.log = []; part.log.push(u.log); }
    if (u.assignedTo !== undefined) part.assignedTo = u.assignedTo || null;
  }
  writeJSON(PROJECTS_FILE, projects);
  res.json({ ok: true });
});

// ── CATCH ALL → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`VE Scheduler running on port ${PORT}`);
});
