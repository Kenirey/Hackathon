/* =============================================================================
   SIGNAL — Community Distress Network
   BACKEND (single file, as required for this hackathon prototype)
   -----------------------------------------------------------------------------
   Everything — Express app, SQLite setup, auth, and all API routes — lives in
   this one file on purpose (see project instructions: no routes/ controllers/
   models/ folders for this prototype).

   Run with:  node server.js
   (see the bottom of this file / the project README for setup steps)
   ============================================================================= */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret-change-me';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AI_API_KEY = process.env.AI_API_KEY || '';
const COOKIE_NAME = 'signal_token';

const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGIN || 'http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:5501,http://localhost:5501')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// --- Forgot / reset password config -------------------------------------
// All email/SMTP configuration comes exclusively from environment
// variables — never hardcode credentials here. See env.example.
const EMAIL_HOST = process.env.EMAIL_HOST;
const EMAIL_PORT = process.env.EMAIL_PORT ? parseInt(process.env.EMAIL_PORT, 10) : 587;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER;
// Base URL of the frontend page that handles the reset link, e.g.
// "http://localhost:5500/reset-password.html" — frontend appends ?token=...
const RESET_URL_BASE = process.env.RESET_URL_BASE || FRONTEND_ORIGINS[0];
// How long a reset token/code stays valid.
const RESET_TOKEN_TTL_MINUTES = process.env.RESET_TOKEN_TTL_MINUTES
  ? parseInt(process.env.RESET_TOKEN_TTL_MINUTES, 10)
  : 30;

/* =============================================================================
   DATABASE SETUP
   ============================================================================= */

const DB_PATH = path.join(__dirname, 'signal.db');
const db = new sqlite3.Database(DB_PATH);

// Small promise wrappers around sqlite3's callback API so the rest of this
// file can use async/await instead of nested callbacks.
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function initDb() {
  await run('PRAGMA foreign_keys = ON');

  await run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    emergency_contact TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS rescuers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT,
    preferred_name TEXT,
    age TEXT,
    phone TEXT,
    email TEXT,
    city TEXT,
    emergency_contact TEXT,
    responder_type TEXT,
    org TEXT,
    years_exp TEXT,
    areas TEXT,
    max_radius TEXT,
    availability TEXT NOT NULL DEFAULT 'available',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    admin_note TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    verified_at INTEGER
  )`);

  await run(`CREATE TABLE IF NOT EXISTS specializations (
    id TEXT PRIMARY KEY,
    rescuer_id TEXT NOT NULL REFERENCES rescuers(id) ON DELETE CASCADE,
    specialization TEXT NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    rescuer_id TEXT NOT NULL REFERENCES rescuers(id) ON DELETE CASCADE,
    credential_name TEXT,
    credential_type TEXT,
    issuing_organization TEXT,
    credential_number TEXT,
    issued_date TEXT,
    expiry_date TEXT,
    notes TEXT,
    verification_status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS signals (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    owner_secret TEXT NOT NULL,
    name TEXT,
    note TEXT,
    category TEXT,
    latitude REAL,
    longitude REAL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    resolved_at INTEGER,
    urgency TEXT,
    incident_type TEXT,
    ai_summary TEXT,
    extracted_facts TEXT,
    self_harm_flag INTEGER DEFAULT 0,
    voice_transcript TEXT,
    audio_data TEXT
  )`);

  await run(`CREATE TABLE IF NOT EXISTS signal_assignments (
    id TEXT PRIMARY KEY,
    signal_id TEXT NOT NULL REFERENCES signals(id) ON DELETE CASCADE,
    rescuer_id TEXT NOT NULL REFERENCES rescuers(id) ON DELETE CASCADE,
    rescuer_name TEXT,
    qualification TEXT,
    accepted_at INTEGER,
    withdrawn_at INTEGER,
    resolved_at INTEGER
  )`);

  // Forgot / reset password — dedicated table rather than columns on
  // `users`, so tokens stay scoped, easy to expire/prune, and never touch
  // the users row until the password is actually changed. Only a HASH of
  // the reset token is stored (never the raw token) so a DB read alone
  // can't be used to reset someone's password.
  await run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash)`);

  await seedAdmin();
}

async function seedAdmin() {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.warn('SIGNAL: ADMIN_EMAIL / ADMIN_PASSWORD not set in .env — no admin account created. Copy .env.example to .env and fill these in.');
    return;
  }
  const existing = await get('SELECT id FROM users WHERE email = ?', [normalizeIdentifier(ADMIN_EMAIL)]);
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  if (existing) {
    // Keep the single admin account's password in sync with .env in case it changed.
    await run('UPDATE users SET password_hash = ?, role = ? WHERE id = ?', [hash, 'admin', existing.id]);
    return;
  }
  await run(
    `INSERT INTO users (id, full_name, email, phone, emergency_contact, password_hash, role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [genId('user'), 'SIGNAL Admin', normalizeIdentifier(ADMIN_EMAIL), null, null, hash, 'admin', Date.now()]
  );
  console.log('SIGNAL: admin account created from .env');
}

/* =============================================================================
   HELPERS
   ============================================================================= */

function genId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}
function normalizeIdentifier(v) {
  return (v || '').toString().trim().toLowerCase();
}
function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}
function fail(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// Minimal cookie parser — avoids pulling in the extra `cookie-parser`
// package for something this small.
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function setAuthCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${token}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}; SameSite=None; Secure`
  );
}

function clearAuthCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=None; Secure`
  );
}

function safeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    phone: row.phone,
    emergencyContact: row.emergency_contact,
    role: row.role,
    createdAt: row.created_at
  };
}

async function getRescuerFull(rescuerRow) {
  if (!rescuerRow) return null;
  const specRows = await all('SELECT specialization FROM specializations WHERE rescuer_id = ?', [rescuerRow.id]);
  const credRows = await all('SELECT * FROM credentials WHERE rescuer_id = ? ORDER BY created_at ASC', [rescuerRow.id]);
  return {
    id: rescuerRow.id,
    userId: rescuerRow.user_id,
    fullName: rescuerRow.full_name,
    preferredName: rescuerRow.preferred_name,
    age: rescuerRow.age,
    phone: rescuerRow.phone,
    email: rescuerRow.email,
    city: rescuerRow.city,
    emergencyContact: rescuerRow.emergency_contact,
    responderType: rescuerRow.responder_type,
    org: rescuerRow.org,
    yearsExp: rescuerRow.years_exp,
    areas: rescuerRow.areas,
    maxRadius: rescuerRow.max_radius,
    availability: rescuerRow.availability,
    verificationStatus: rescuerRow.verification_status,
    adminNote: rescuerRow.admin_note || '',
    createdAt: rescuerRow.created_at,
    verifiedAt: rescuerRow.verified_at,
    specializations: specRows.map(r => r.specialization),
    credentials: credRows.map(c => ({
      id: c.id,
      name: c.credential_name,
      type: c.credential_type,
      org: c.issuing_organization,
      number: c.credential_number,
      issued: c.issued_date,
      expiry: c.expiry_date,
      notes: c.notes,
      status: c.verification_status,
      createdAt: c.created_at
    }))
  };
}

function signalToJson(row) {
  return {
    id: row.id,
    name: row.name,
    note: row.note,
    category: row.category,
    lat: row.latitude,
    lng: row.longitude,
    status: row.status,
    createdAt: row.created_at,
    resolvedAt: row.resolved_at,
    audioDataUrl: row.audio_data || null,
    voiceTranscript: row.voice_transcript || null,
    assignedRescuerId: row.assigned_rescuer_id || null,
    assignedRescuerName: row.assigned_rescuer_name || null,
    assignedQualification: row.assigned_qualification || null,
    acceptedAt: row.accepted_at || null,
    triage: row.urgency ? {
      urgency: row.urgency,
      incident_type: row.incident_type,
      summary: row.ai_summary,
      extracted_facts: row.extracted_facts ? JSON.parse(row.extracted_facts) : [],
      self_harm_flag: !!row.self_harm_flag
    } : null
  };
}

// Joins a signal row with its current (non-withdrawn, non-resolved) assignment,
// so the API can return assignedRescuerId/Name/Qualification/acceptedAt like
// the original frontend prototype expected on the signal object itself.
async function getSignalWithAssignment(signalId) {
  const sig = await get('SELECT * FROM signals WHERE id = ?', [signalId]);
  if (!sig) return null;
  const assignment = await get(
    `SELECT * FROM signal_assignments WHERE signal_id = ? AND withdrawn_at IS NULL ORDER BY accepted_at DESC LIMIT 1`,
    [signalId]
  );
  const merged = {
    ...sig,
    assigned_rescuer_id: assignment ? assignment.rescuer_id : null,
    assigned_rescuer_name: assignment ? assignment.rescuer_name : null,
    assigned_qualification: assignment ? assignment.qualification : null,
    accepted_at: assignment ? assignment.accepted_at : null
  };
  return signalToJson(merged);
}

/* =============================================================================
   FORGOT / RESET PASSWORD — helpers
   ============================================================================= */

// Lazily-created singleton transporter. If SMTP isn't configured (e.g. in a
// fresh dev checkout with no .env yet), this stays null and
// sendPasswordResetEmail() below just no-ops with a warning instead of
// throwing — the rest of SIGNAL keeps working without email configured.
let mailTransporter = null;
function getMailTransporter() {
  if (mailTransporter) return mailTransporter;
  if (!EMAIL_HOST || !EMAIL_USER || !EMAIL_PASSWORD) return null;
  mailTransporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: EMAIL_PORT === 465, // true for port 465 (implicit TLS), false for 587/25 (STARTTLS)
    auth: { user: EMAIL_USER, pass: EMAIL_PASSWORD }
  });
  return mailTransporter;
}

// Generates a cryptographically secure raw reset token and its SHA-256 hash.
// Only the hash is ever persisted to the database; the raw token is emailed
// to the user once and never stored or logged.
function generateResetToken() {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  return { rawToken, tokenHash };
}

async function sendPasswordResetEmail(toEmail, rawToken) {
  console.log('SIGNAL: password reset email attempt started');

  const transporter = getMailTransporter();

  if (!transporter) {
    console.error('SIGNAL: mail transporter is NOT configured');
    return false;
  }

  console.log('SIGNAL: mail transporter configured');

  const resetLink = `${RESET_URL_BASE}?token=${encodeURIComponent(rawToken)}`;

  try {
    const info = await transporter.sendMail({
      from: EMAIL_FROM,
      to: toEmail,
      subject: 'SIGNAL — Reset your password',
      text:
        `We received a request to reset your SIGNAL account password.\n\n` +
        `Reset your password using this link (expires in ${RESET_TOKEN_TTL_MINUTES} minutes):\n${resetLink}\n\n` +
        `If you did not request this, you can safely ignore this email — your password will not be changed.`,
      html:
        `<p>We received a request to reset your SIGNAL account password.</p>` +
        `<p><a href="${resetLink}">Click here to reset your password</a> (expires in ${RESET_TOKEN_TTL_MINUTES} minutes).</p>` +
        `<p>If you did not request this, you can safely ignore this email — your password will not be changed.</p>`
    });

    console.log('SIGNAL: password reset email sent:', info.messageId);
    return true;

  } catch (e) {
    console.error('SIGNAL: SMTP SEND ERROR:', e.message);
    throw e;
  }
}

/* =============================================================================
   AI TRIAGE (assistive only — never the sole basis for an irreversible action)
   ============================================================================= */

const TRIAGE_SYSTEM_PROMPT = `You are a triage assistant for a community emergency-response board. A person in distress has submitted an optional free-text note along with their SOS signal. Convert it into a short structured summary a responder can scan in under two seconds. You do not contact anyone, give medical advice, verify anyone's real-world credentials, or take any action.

Classify urgency as one of: "critical" (immediate danger to life), "urgent" (needs help soon, not seconds-count), "unclear" (too vague to classify), "not-distress" (note doesn't describe an emergency).
Classify incident_type as one of: "medical", "fire", "search_rescue", "water", "disaster", "security", "mental_health", "general", "unknown". Use "unknown" whenever the category is not clearly stated.
Extract only facts stated in the note — never infer or add details.
Write a one-sentence summary, max 20 words.
If the note mentions self-harm or suicidal intent, set urgency to "critical", self_harm_flag to true, and incident_type to "mental_health".
If the note is empty, urgency is "unclear", incident_type is "unknown", and summary is "No details provided."

Respond with ONLY valid JSON, no preamble, no markdown fences:
{"urgency":"critical"|"urgent"|"unclear"|"not-distress","incident_type":"medical"|"fire"|"search_rescue"|"water"|"disaster"|"security"|"mental_health"|"general"|"unknown","summary":"string","extracted_facts":["string"],"self_harm_flag":true|false}`;

const VALID_INCIDENT_TYPES = ['medical', 'fire', 'search_rescue', 'water', 'disaster', 'security', 'mental_health', 'general', 'unknown'];

// Development fallback: simple keyword-based triage used whenever no
// AI_API_KEY is configured, or the AI call fails, so the rest of SIGNAL
// keeps working without an API key.
function fallbackTriage(note) {
  const text = (note || '').toLowerCase();
  if (!text.trim()) {
    return { urgency: 'unclear', incident_type: 'unknown', summary: 'No details provided.', extracted_facts: [], self_harm_flag: false };
  }
  const selfHarm = /(suicide|kill myself|end my life|self[\s-]?harm|want to die)/.test(text);
  let incident_type = 'unknown';
  if (/(fire|smoke|burn)/.test(text)) incident_type = 'fire';
  else if (/(flood|drown|water|river|current)/.test(text)) incident_type = 'water';
  else if (/(injur|hurt|bleed|pain|medical|breath|heart|unconscious)/.test(text)) incident_type = 'medical';
  else if (/(trapped|collapse|earthquake|landslide)/.test(text)) incident_type = 'disaster';
  else if (/(attack|robbery|weapon|threat|assault)/.test(text)) incident_type = 'security';
  else if (/(lost|missing|search)/.test(text)) incident_type = 'search_rescue';
  if (selfHarm) incident_type = 'mental_health';
  const urgency = selfHarm ? 'critical' : (incident_type === 'unknown' ? 'unclear' : 'urgent');
  return {
    urgency,
    incident_type,
    summary: note.slice(0, 120),
    extracted_facts: [],
    self_harm_flag: selfHarm,
    triage_failed: !AI_API_KEY
  };
}

async function triageNote(note) {
  if (!note || !note.trim()) {
    return { urgency: 'unclear', incident_type: 'unknown', summary: 'No details provided.', extracted_facts: [], self_harm_flag: false };
  }
  if (!AI_API_KEY) {
    return fallbackTriage(note);
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': AI_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 300,
        system: TRIAGE_SYSTEM_PROMPT,
        messages: [{ role: 'user', content: note }]
      })
    });
    const data = await response.json();
    const textBlock = (data.content || []).find(b => b.type === 'text');
    if (!textBlock) throw new Error('no text block in AI response');
    const cleaned = textBlock.text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(cleaned);
    if (!VALID_INCIDENT_TYPES.includes(parsed.incident_type)) parsed.incident_type = 'unknown';
    return parsed;
  } catch (e) {
    console.warn('SIGNAL: AI triage failed, using fallback —', e.message);
    return fallbackTriage(note);
  }
}

/* =============================================================================
   EXPRESS APP
   ============================================================================= */

const app = express();
app.use(express.json({ limit: '15mb' })); // generous limit: base64 voice-note audio can be a few MB
app.use(cors({
  origin: FRONTEND_ORIGINS,
  credentials: true
}));

// Attaches req.user (from the JWT cookie) if present. Does NOT block the
// request — individual routes decide whether auth is required.
app.use((req, res, next) => {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      req.user = null;
    }
  } else {
    req.user = null;
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.user) return fail(res, 'You must be logged in.', 401);
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user) return fail(res, 'You must be logged in.', 401);
  if (req.user.role !== 'admin') return fail(res, 'Admin access only.', 403);
  next();
}

/* -----------------------------------------------------------------------
   HEALTH
   ----------------------------------------------------------------------- */
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'SIGNAL backend is running' });
});

/* -----------------------------------------------------------------------
   AUTH
   ----------------------------------------------------------------------- */

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, phone, emergencyContact, password } = req.body || {};
    if (!fullName || !fullName.trim()) return fail(res, 'Full name is required.');
    if (!password || password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return fail(res, 'Password must be at least 8 characters and include a letter and a number.');
    }
    if (!email && !phone) return fail(res, 'Email or phone number is required.');

    const normEmail = email ? normalizeIdentifier(email) : null;
    const normPhone = phone ? phone.trim() : null;

    if (normEmail) {
      const existing = await get('SELECT id FROM users WHERE email = ?', [normEmail]);
      if (existing) return fail(res, 'An account with that email already exists.', 409);
    }
    if (normPhone) {
      const existing = await get('SELECT id FROM users WHERE phone = ?', [normPhone]);
      if (existing) return fail(res, 'An account with that phone number already exists.', 409);
    }

    const hash = await bcrypt.hash(password, 10);
    const id = genId('user');
    await run(
      `INSERT INTO users (id, full_name, email, phone, emergency_contact, password_hash, role, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'user', ?)`,
      [id, fullName.trim(), normEmail, normPhone, emergencyContact || null, hash, Date.now()]
    );
    const user = await get('SELECT * FROM users WHERE id = ?', [id]);
    const token = signToken(user);
    setAuthCookie(res, token);
    ok(res, safeUser(user), 201);
  } catch (e) {
    console.error(e);
    fail(res, 'Could not create account.', 500);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) return fail(res, 'Email/phone and password are required.');
    const idNorm = normalizeIdentifier(identifier);
    const user = await get('SELECT * FROM users WHERE email = ? OR phone = ?', [idNorm, identifier.trim()]);
    if (!user) return fail(res, "We couldn't find an account with that email/phone and password.", 401);
    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) return fail(res, "We couldn't find an account with that email/phone and password.", 401);
    const token = signToken(user);
    setAuthCookie(res, token);
    ok(res, safeUser(user));
  } catch (e) {
    console.error(e);
    fail(res, 'Login failed.', 500);
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  ok(res, null);
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!user) return fail(res, 'Account not found.', 404);
  ok(res, safeUser(user));
});

/* -----------------------------------------------------------------------
   FORGOT / RESET PASSWORD
   ----------------------------------------------------------------------- */

// Always responds with the same generic message regardless of whether the
// email is registered, to avoid account enumeration.
const FORGOT_PASSWORD_GENERIC_MESSAGE =
  'If an account with that email exists, a password reset link has been sent.';
const EMAIL_FORMAT_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    const normEmail = normalizeIdentifier(email);

    // Invalid/missing email still gets the generic response — never reveal
    // *why* nothing happened.
    if (!normEmail || !EMAIL_FORMAT_RE.test(normEmail)) {
      return ok(res, { message: FORGOT_PASSWORD_GENERIC_MESSAGE });
    }

    const user = await get('SELECT * FROM users WHERE email = ?', [normEmail]);

    console.log('SIGNAL: forgot-password request received');
    console.log('SIGNAL: account lookup:', user ? 'FOUND' : 'NOT FOUND');
    if (user) {
      // Invalidate any still-outstanding tokens for this user before
      // issuing a new one, so only the newest reset link/code works.
      await run('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0', [user.id]);

      const { rawToken, tokenHash } = generateResetToken();
      const expiresAt = Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000;

      await run(
        `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used, created_at)
         VALUES (?, ?, ?, ?, 0, ?)`,
        [genId('prt'), user.id, tokenHash, expiresAt, Date.now()]
      );

      // Fire-and-forget: an email delivery failure shouldn't leak account
      // existence back to the caller via a different response/timing.
      sendPasswordResetEmail(user.email, rawToken).catch(e => {
        console.error('SIGNAL: failed to send password reset email —', e.message);
      });
    }

    ok(res, { message: FORGOT_PASSWORD_GENERIC_MESSAGE });
  } catch (e) {
    console.error(e);
    // Keep the response generic even on unexpected errors.
    ok(res, { message: FORGOT_PASSWORD_GENERIC_MESSAGE });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || typeof token !== 'string') {
      return fail(res, 'This reset link is invalid or has expired.', 400);
    }
    if (!password || password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return fail(res, 'Password must be at least 8 characters and include a letter and a number.');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await get('SELECT * FROM password_reset_tokens WHERE token_hash = ?', [tokenHash]);

    if (!record || record.used || record.expires_at < Date.now()) {
      return fail(res, 'This reset link is invalid or has expired.', 400);
    }

    const hash = await bcrypt.hash(password, 10);
    await run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, record.user_id]);

    // Single-use: mark this token (and any other outstanding tokens for
    // the same user) as used so it can never be replayed.
    await run('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0', [record.user_id]);

    ok(res, { message: 'Your password has been reset. You can now log in.' });
  } catch (e) {
    console.error(e);
    fail(res, 'Could not reset password.', 500);
  }
});

/* -----------------------------------------------------------------------
   RESCUERS
   ----------------------------------------------------------------------- */

app.post('/api/rescuers', requireAuth, async (req, res) => {
  try {
    const existing = await get('SELECT id FROM rescuers WHERE user_id = ?', [req.user.id]);
    if (existing) return fail(res, 'You already have a rescuer profile.', 409);

    const b = req.body || {};
    if (!b.fullName || !b.fullName.trim()) return fail(res, 'Full name is required.');
    if (!b.phone || !b.phone.trim()) return fail(res, 'Contact number is required.');
    if (!b.email || !b.email.trim()) return fail(res, 'Email is required.');
    if (!b.responderType || !b.responderType.trim()) return fail(res, 'Responder type is required.');

    const id = genId('rescuer');
    await run(
      `INSERT INTO rescuers (id, user_id, full_name, preferred_name, age, phone, email, city, emergency_contact,
        responder_type, org, years_exp, areas, max_radius, availability, verification_status, admin_note, created_at, verified_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'available', 'pending', '', ?, NULL)`,
      [id, req.user.id, b.fullName.trim(), b.preferredName || '', b.age || '', b.phone.trim(), b.email.trim(),
       b.city || '', b.emergencyContact || '', b.responderType, b.org || '', b.yearsExp || '', b.areas || '',
       b.maxRadius || '', Date.now()]
    );

    const specs = Array.isArray(b.specializations) ? b.specializations : [];
    for (const s of specs) {
      if (!s) continue;
      await run('INSERT INTO specializations (id, rescuer_id, specialization) VALUES (?, ?, ?)', [genId('spec'), id, s]);
    }

    const creds = Array.isArray(b.credentials) ? b.credentials : [];
    for (const c of creds) {
      await run(
        `INSERT INTO credentials (id, rescuer_id, credential_name, credential_type, issuing_organization,
          credential_number, issued_date, expiry_date, notes, verification_status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
        [genId('cred'), id, c.name || '', c.type || 'Certification', c.org || '', c.number || '', c.issued || '',
         c.expiry || '', c.notes || '', Date.now()]
      );
    }

    const row = await get('SELECT * FROM rescuers WHERE id = ?', [id]);
    ok(res, await getRescuerFull(row), 201);
  } catch (e) {
    console.error(e);
    fail(res, 'Could not submit rescuer registration.', 500);
  }
});

app.get('/api/rescuers/me', requireAuth, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  if (!row) return fail(res, 'No rescuer profile found.', 404);
  ok(res, await getRescuerFull(row));
});

app.put('/api/rescuers/me', requireAuth, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  if (!row) return fail(res, 'No rescuer profile found.', 404);
  const b = req.body || {};
  const allowed = ['preferred_name', 'age', 'phone', 'email', 'city', 'emergency_contact', 'org', 'years_exp', 'areas', 'max_radius', 'availability'];
  const fieldMap = { preferredName: 'preferred_name', emergencyContact: 'emergency_contact', yearsExp: 'years_exp', maxRadius: 'max_radius' };
  const sets = [];
  const params = [];
  for (const [key, value] of Object.entries(b)) {
    const col = fieldMap[key] || (allowed.includes(key) ? key : null);
    if (col && allowed.includes(col)) {
      sets.push(`${col} = ?`);
      params.push(value);
    }
  }
  if (b.availability && !['available', 'busy', 'offline'].includes(b.availability)) {
    return fail(res, 'Invalid availability value.');
  }
  if (sets.length) {
    params.push(row.id);
    await run(`UPDATE rescuers SET ${sets.join(', ')} WHERE id = ?`, params);
  }
  const updated = await get('SELECT * FROM rescuers WHERE id = ?', [row.id]);
  ok(res, await getRescuerFull(updated));
});

app.post('/api/rescuers/me/credentials', requireAuth, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  if (!row) return fail(res, 'No rescuer profile found.', 404);
  const c = req.body || {};
  const id = genId('cred');
  await run(
    `INSERT INTO credentials (id, rescuer_id, credential_name, credential_type, issuing_organization,
      credential_number, issued_date, expiry_date, notes, verification_status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
    [id, row.id, c.name || '', c.type || 'Certification', c.org || '', c.number || '', c.issued || '',
     c.expiry || '', c.notes || '', Date.now()]
  );
  ok(res, await getRescuerFull(row), 201);
});

app.get('/api/rescuers/me/credentials', requireAuth, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  if (!row) return fail(res, 'No rescuer profile found.', 404);
  const full = await getRescuerFull(row);
  ok(res, full.credentials);
});

/* -----------------------------------------------------------------------
   SIGNALS (SOS)
   ----------------------------------------------------------------------- */

app.post('/api/signals', async (req, res) => {
  try {
    const b = req.body || {};
    const id = genId('sig');
    const ownerSecret = crypto.randomBytes(16).toString('hex');
    const note = (b.note || '').toString().slice(0, 280);

    // AI triage runs synchronously here so the very first GET /api/signals
    // already reflects it — the frontend polling loop needs no separate
    // triage call.
    const triage = await triageNote(note);

    await run(
      `INSERT INTO signals (id, user_id, owner_secret, name, note, category, latitude, longitude, status,
        created_at, resolved_at, urgency, incident_type, ai_summary, extracted_facts, self_harm_flag,
        voice_transcript, audio_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.user ? req.user.id : null, ownerSecret, (b.name || 'Anonymous').toString().slice(0, 60), note,
       b.category || null, b.lat != null ? b.lat : null, b.lng != null ? b.lng : null, Date.now(),
       triage.urgency, triage.incident_type, triage.summary, JSON.stringify(triage.extracted_facts || []),
       triage.self_harm_flag ? 1 : 0, b.voiceTranscript || null, b.audioDataUrl || null]
    );

    const signal = await getSignalWithAssignment(id);
    ok(res, { ...signal, ownerSecret }, 201);
  } catch (e) {
    console.error(e);
    fail(res, 'Could not create signal.', 500);
  }
});

app.get('/api/signals', async (req, res) => {
  const rows = await all('SELECT id FROM signals ORDER BY created_at DESC');
  const signals = [];
  for (const r of rows) signals.push(await getSignalWithAssignment(r.id));
  ok(res, signals);
});

app.get('/api/signals/:id', async (req, res) => {
  const signal = await getSignalWithAssignment(req.params.id);
  if (!signal) return fail(res, 'Signal not found.', 404);
  ok(res, signal);
});

app.post('/api/signals/:id/audio', async (req, res) => {
  try {
    const row = await get('SELECT * FROM signals WHERE id = ?', [req.params.id]);
    if (!row) return fail(res, 'Signal not found.', 404);
    const { audioDataUrl, transcript, ownerSecret } = req.body || {};
    if (ownerSecret !== row.owner_secret) return fail(res, 'Not authorized to update this signal.', 403);

    const combinedNote = [row.note, transcript].filter(Boolean).join('. ');
    const triage = await triageNote(combinedNote);

    await run(
      `UPDATE signals SET audio_data = ?, voice_transcript = ?, urgency = ?, incident_type = ?,
        ai_summary = ?, extracted_facts = ?, self_harm_flag = ?,
        category = COALESCE(category, ?)
       WHERE id = ?`,
      [audioDataUrl || null, transcript || '', triage.urgency, triage.incident_type, triage.summary,
       JSON.stringify(triage.extracted_facts || []), triage.self_harm_flag ? 1 : 0, triage.incident_type, row.id]
    );
    ok(res, await getSignalWithAssignment(row.id));
  } catch (e) {
    console.error(e);
    fail(res, 'Could not attach voice update.', 500);
  }
});

app.post('/api/signals/:id/accept', requireAuth, async (req, res) => {
  try {
    const rescuer = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
    if (!rescuer) return fail(res, 'Only registered rescuers can accept emergencies.', 403);

    const signal = await get('SELECT * FROM signals WHERE id = ?', [req.params.id]);
    if (!signal) return fail(res, 'Signal not found.', 404);
    if (signal.status !== 'active') {
      return fail(res, 'This emergency has already been assigned to another responder.', 409);
    }

    // Prevent a race between two responders accepting simultaneously: only
    // succeed if this UPDATE actually flips a still-active row.
    const result = await run(`UPDATE signals SET status = 'responding' WHERE id = ? AND status = 'active'`, [signal.id]);
    if (result.changes === 0) {
      return fail(res, 'This emergency has already been assigned to another responder.', 409);
    }

    const category = signal.category || signal.incident_type || 'unknown';
    const specRows = await all('SELECT specialization FROM specializations WHERE rescuer_id = ?', [rescuer.id]);
    const QUALIFICATION_TO_CATEGORY = {
      medical: ['First Aid', 'CPR', 'Basic Life Support', 'Advanced Life Support', 'Medical Response'],
      fire: ['Fire Rescue', 'Disaster Response', 'Technical Rescue'],
      search_rescue: ['Search and Rescue', 'Disaster Response', 'Technical Rescue'],
      water: ['Water Rescue', 'Disaster Response'],
      disaster: ['Disaster Response', 'Search and Rescue', 'Fire Rescue', 'Water Rescue'],
      security: ['Security/Evacuation'],
      mental_health: ['Mental Health/Crisis Response'],
      general: [], unknown: []
    };
    const needed = QUALIFICATION_TO_CATEGORY[category] || [];
    const matched = specRows.map(r => r.specialization).filter(s => needed.includes(s));
    const qualification = matched.length ? matched.join(', ') : (rescuer.responder_type || 'General assistance');

    const assignmentId = genId('assign');
    const now = Date.now();
    await run(
      `INSERT INTO signal_assignments (id, signal_id, rescuer_id, rescuer_name, qualification, accepted_at, withdrawn_at, resolved_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
      [assignmentId, signal.id, rescuer.id, rescuer.preferred_name || rescuer.full_name, qualification, now]
    );

    ok(res, await getSignalWithAssignment(signal.id));
  } catch (e) {
    console.error(e);
    fail(res, 'Could not accept signal.', 500);
  }
});

app.post('/api/signals/:id/withdraw', requireAuth, async (req, res) => {
  const rescuer = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  if (!rescuer) return fail(res, 'Only registered rescuers can withdraw.', 403);
  const signal = await get('SELECT * FROM signals WHERE id = ?', [req.params.id]);
  if (!signal) return fail(res, 'Signal not found.', 404);

  const assignment = await get(
    `SELECT * FROM signal_assignments WHERE signal_id = ? AND rescuer_id = ? AND withdrawn_at IS NULL ORDER BY accepted_at DESC LIMIT 1`,
    [signal.id, rescuer.id]
  );
  if (!assignment) return fail(res, 'You are not the assigned responder for this signal.', 403);

  await run('UPDATE signal_assignments SET withdrawn_at = ? WHERE id = ?', [Date.now(), assignment.id]);
  await run(`UPDATE signals SET status = 'active' WHERE id = ?`, [signal.id]);
  ok(res, await getSignalWithAssignment(signal.id));
});

app.post('/api/signals/:id/resolve', requireAuth, async (req, res) => {
  const rescuer = await get('SELECT * FROM rescuers WHERE user_id = ?', [req.user.id]);
  const signal = await get('SELECT * FROM signals WHERE id = ?', [req.params.id]);
  if (!signal) return fail(res, 'Signal not found.', 404);

  const isAdmin = req.user.role === 'admin';
  let assignment = null;
  if (rescuer) {
    assignment = await get(
      `SELECT * FROM signal_assignments WHERE signal_id = ? AND rescuer_id = ? AND withdrawn_at IS NULL ORDER BY accepted_at DESC LIMIT 1`,
      [signal.id, rescuer.id]
    );
  }
  if (!isAdmin && !assignment) {
    return fail(res, 'Only the assigned responder or an admin can resolve this signal.', 403);
  }

  const now = Date.now();
  await run(`UPDATE signals SET status = 'resolved', resolved_at = ? WHERE id = ?`, [now, signal.id]);
  if (assignment) await run('UPDATE signal_assignments SET resolved_at = ? WHERE id = ?', [now, assignment.id]);
  ok(res, await getSignalWithAssignment(signal.id));
});

// "I'M SAFE / RESCUED" — the person who created the signal closes their own
// emergency. Authorized with the per-signal ownerSecret (issued at creation)
// rather than a login, since sending an SOS never requires an account.
app.post('/api/signals/:id/safe', async (req, res) => {
  const signal = await get('SELECT * FROM signals WHERE id = ?', [req.params.id]);
  if (!signal) return fail(res, 'Signal not found.', 404);
  const { ownerSecret } = req.body || {};
  if (ownerSecret !== signal.owner_secret) return fail(res, 'Not authorized to close this signal.', 403);
  await run(`UPDATE signals SET status = 'resolved', resolved_at = ? WHERE id = ?`, [Date.now(), signal.id]);
  ok(res, await getSignalWithAssignment(signal.id));
});

/* -----------------------------------------------------------------------
   AI TRIAGE (standalone endpoint, e.g. for re-triaging or manual testing)
   ----------------------------------------------------------------------- */
app.post('/api/triage', async (req, res) => {
  const { note } = req.body || {};
  const triage = await triageNote(note || '');
  ok(res, triage);
});

/* -----------------------------------------------------------------------
   ADMIN — responder & credential verification (admin role only)
   ----------------------------------------------------------------------- */

app.get('/api/admin/rescuers', requireAdmin, async (req, res) => {
  const rows = await all('SELECT * FROM rescuers ORDER BY created_at DESC');
  const out = [];
  for (const r of rows) out.push(await getRescuerFull(r));
  ok(res, out);
});

app.get('/api/admin/rescuers/pending', requireAdmin, async (req, res) => {
  const rows = await all(`SELECT * FROM rescuers WHERE verification_status = 'pending' ORDER BY created_at ASC`);
  const out = [];
  for (const r of rows) out.push(await getRescuerFull(r));
  ok(res, out);
});

app.get('/api/admin/rescuers/:id', requireAdmin, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE id = ?', [req.params.id]);
  if (!row) return fail(res, 'Rescuer not found.', 404);
  ok(res, await getRescuerFull(row));
});

app.patch('/api/admin/rescuers/:id/verify', requireAdmin, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE id = ?', [req.params.id]);
  if (!row) return fail(res, 'Rescuer not found.', 404);
  await run(`UPDATE rescuers SET verification_status = 'verified', admin_note = '', verified_at = ? WHERE id = ?`, [Date.now(), row.id]);
  ok(res, await getRescuerFull(await get('SELECT * FROM rescuers WHERE id = ?', [row.id])));
});

app.patch('/api/admin/rescuers/:id/reject', requireAdmin, async (req, res) => {
  const row = await get('SELECT * FROM rescuers WHERE id = ?', [req.params.id]);
  if (!row) return fail(res, 'Rescuer not found.', 404);
  const { note, status } = req.body || {};
  // `status` lets the admin UI's "request more info" action reuse this same
  // endpoint to set the rescuer back to "pending" with a note, instead of a
  // hard rejection — both are just "not yet verified, here's why".
  const nextStatus = status === 'pending' ? 'pending' : 'rejected';
  await run(`UPDATE rescuers SET verification_status = ?, admin_note = ? WHERE id = ?`, [nextStatus, note || '', row.id]);
  ok(res, await getRescuerFull(await get('SELECT * FROM rescuers WHERE id = ?', [row.id])));
});

app.get('/api/admin/credentials/pending', requireAdmin, async (req, res) => {
  const rows = await all(`SELECT * FROM credentials WHERE verification_status = 'pending' ORDER BY created_at ASC`);
  ok(res, rows.map(c => ({
    id: c.id, rescuerId: c.rescuer_id, name: c.credential_name, type: c.credential_type,
    org: c.issuing_organization, number: c.credential_number, issued: c.issued_date,
    expiry: c.expiry_date, notes: c.notes, status: c.verification_status, createdAt: c.created_at
  })));
});

app.patch('/api/admin/credentials/:id/verify', requireAdmin, async (req, res) => {
  const row = await get('SELECT * FROM credentials WHERE id = ?', [req.params.id]);
  if (!row) return fail(res, 'Credential not found.', 404);
  await run(`UPDATE credentials SET verification_status = 'verified' WHERE id = ?`, [row.id]);
  ok(res, { id: row.id, status: 'verified' });
});

app.patch('/api/admin/credentials/:id/reject', requireAdmin, async (req, res) => {
  const row = await get('SELECT * FROM credentials WHERE id = ?', [req.params.id]);
  if (!row) return fail(res, 'Credential not found.', 404);
  await run(`UPDATE credentials SET verification_status = 'rejected' WHERE id = ?`, [row.id]);
  ok(res, { id: row.id, status: 'rejected' });
});

// Fallback for unknown API routes.
app.use('/api', (req, res) => fail(res, 'Not found.', 404));

/* =============================================================================
   START
   ============================================================================= */
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`SIGNAL backend running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('SIGNAL: failed to initialize database', err);
    process.exit(1);
  });
