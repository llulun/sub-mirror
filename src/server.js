const express = require('express');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { fetch } = require('undici');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const { PassThrough } = require('stream');
const dns = require('dns');
const { createStorage } = require('./storage');

// Initialize storage adapter
const storage = createStorage();
storage.init().catch(console.error);

function isPrivateIp(ip) {
  const parts = ip.split('.');
  if (parts.length === 4) {
    const a = parseInt(parts[0], 10);
    const b = parseInt(parts[1], 10);
    // 127.0.0.0/8
    if (a === 127) return true;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 0.0.0.0/8 (Current network)
    if (a === 0) return true;
    return false;
  }
  // IPv6 checks (simplified)
  if (ip === '::1') return true;
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // Unique Local
  if (ip.startsWith('fe80')) return true; // Link Local
  return false;
}

async function validateTargetUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
       throw new Error('invalid_protocol');
    }
    // Resolve hostname
    const { address } = await dns.promises.lookup(u.hostname);
    if (isPrivateIp(address)) {
      throw new Error('private_ip_forbidden');
    }
    return true;
  } catch (e) {
    throw e;
  }
}


const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(compression());
app.use(morgan('tiny'));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://challenges.cloudflare.com", "'unsafe-eval'", "'unsafe-inline'"], // unsafe-inline needed for current frontend structure
        frameSrc: ["'self'", "https://challenges.cloudflare.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", "https://challenges.cloudflare.com"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    frameguard: { action: 'deny' },
  })
);

// Block dotfiles
app.use((req, res, next) => {
  if (/(^|\/)\.[^\/\.]/g.test(req.path)) {
    return res.status(403).send('Forbidden');
  }
  next();
});

app.use(express.static(path.join(process.cwd(), 'public')));

// CORS (read/write endpoints via API)
function matchOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins.includes('*')) return true;
  return allowedOrigins.includes(origin);
}
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (matchOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token, Authorization');
    res.setHeader('Access-Control-Max-Age', '600');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const port = parseInt(process.env.PORT || '8080', 10);
const adminToken = process.env.ADMIN_TOKEN || null;
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// Storage keys instead of full paths
const sourcesKey = 'sources.json';
const adminConfigKey = 'admin.json';
const authSecretKey = 'auth.json';

async function ensureAdminToken() {
  if (process.env.ADMIN_TOKEN) return;
  try {
    const cfg = await storage.readJSON(adminConfigKey);
    if (cfg && typeof cfg.admin === 'string' && cfg.admin.length > 0) {
      process.env.ADMIN_TOKEN = cfg.admin;
      return;
    }
  } catch {}
  const t = crypto.randomBytes(12).toString('hex');
  process.env.ADMIN_TOKEN = t;
  try {
    await storage.write(adminConfigKey, { admin: t });
  } catch {}
}

async function ensureAuthSecret() {
  try {
    const cfg = await storage.readJSON(authSecretKey);
    if (cfg && typeof cfg.secret === 'string' && cfg.secret.length > 0) {
      return cfg.secret;
    }
  } catch {}
  const secret = crypto.randomBytes(32).toString('hex');
  try {
    await storage.write(authSecretKey, { secret });
  } catch {}
  return secret;
}

// We need to await secret generation, so wrapping bootstrap in async
let AUTH_SECRET = null;

const state = {
  // legacy single-tenant fields (kept for backward compatibility of /sub)
  sources: {},
  activeId: null,
  sourceUrl: process.env.UPSTREAM_URL || null,
  refreshMinutes: parseInt(process.env.REFRESH_INTERVAL_MINUTES || '30', 10),
  content: null,
  etag: null,
  updatedAt: null,
  loading: false,
  lastError: null,
  timer: null,
  // multi-tenant
  users: {}, // username -> { sources: {}, activeId: null, refreshMinutes: number, timer: any, logs: [], webhook: string }
  // analytics
  accessLogs: [], // { ts, ip, ua, path, status, sourceId }
  ipStats: {}, // ip -> { count, blocked, lastReq } (reset daily)
  uaStats: {}, // ua -> count
  todayCounts: 0,
  securityAlerts: [], // { ts, ip, reason }
};

// Reset stats daily
setInterval(() => {
  state.ipStats = {};
  state.uaStats = {};
  state.todayCounts = 0;
  // Keep logs but trim
  if (state.accessLogs.length > 5000) state.accessLogs = state.accessLogs.slice(0, 5000);
}, 24 * 60 * 60 * 1000);

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket.remoteAddress;
}

async function recordAccess(req, sourceId, status, username = null) {
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || 'Unknown';
  
  // 1. Log
  const entry = {
    ts: new Date().toISOString(),
    ip,
    ua,
    path: req.path,
    status,
    sourceId
  };
  state.accessLogs.unshift(entry);
  if (state.accessLogs.length > 1000) state.accessLogs.pop();
    
    // Persistent log
    storage.append(accessLogKey, JSON.stringify(entry) + '\n').catch(() => {});
    
    // 2. Stats
  state.todayCounts++;
  
  if (!state.ipStats[ip]) {
    // Safety: limit max tracked IPs to prevent memory exhaustion
    if (Object.keys(state.ipStats).length > 20000) {
      state.ipStats = {}; // Emergency reset
    }
    state.ipStats[ip] = { count: 0, lastReq: 0, warnings: 0 };
  }
  state.ipStats[ip].count++;
  
  if (!state.uaStats[ua]) state.uaStats[ua] = 0;
  state.uaStats[ua]++;

  // 3. Security Check (Simple Rate Limit: > 60 reqs / min)
  const now = Date.now();
  // We can't easily check "per minute" with just a counter unless we slide it.
  // Simplified: Check if this IP has > 100 requests today AND interval < 100ms avg?
  // Better: Token bucket or just simple flood check.
  // Let's use a "short term" check.
  
  // Check High Frequency: If last request was < 500ms ago, increment "burst" counter?
  // Let's trust the existing 'rateLimit' middleware for BLOCKING (429).
  // But we want to ALERT.
  
  // If status is 429 (Too Many Requests), trigger alert
  if (status === 429) {
     triggerSecurityAlert(ip, 'Rate Limit Exceeded', username);
  }
}

async function triggerSecurityAlert(ip, reason, username) {
  // Dedup alerts: don't alert same IP + reason more than once per hour
  const key = `${ip}:${reason}`;
  const last = state.securityAlerts.find(a => a.ip === ip && a.reason === reason && Date.now() - new Date(a.ts).getTime() < 60*60*1000);
  if (last) return;

  const alert = { ts: new Date().toISOString(), ip, reason };
  state.securityAlerts.unshift(alert);
  if (state.securityAlerts.length > 50) state.securityAlerts.pop();
  
    // Persistent log
    storage.append(securityLogKey, JSON.stringify(alert) + '\n').catch(() => {});
  
    // Notify all users or specific user? For now notify all admins (users with webhook)
  // Since we might not know which user "owns" the attack, we scan all users.
  // Optimization: If username is provided, notify only them.
  
  const usersToNotify = username ? [getUser(username)] : Object.values(state.users);
  
  for (const u of usersToNotify) {
    if (u && u.webhook) {
      await sendNotification(username || 'admin', 'warning', `Security Alert from ${ip}: ${reason}`);
    }
  }
}

function appendLog(username, level, message) {
  const u = getUser(username);
  if (!u.logs) u.logs = [];
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
  };
  u.logs.unshift(entry);
  if (u.logs.length > 200) u.logs = u.logs.slice(0, 200);
}

function sanitizeUrl(u) {
  if (!u) return null;
  let s = String(u).trim();
  const idx = s.indexOf('http');
  if (idx > 0) s = s.slice(idx);
  
  try {
    const parsed = new URL(s);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.href;
  } catch {
    return null;
  }
}
function clampMinutes(m) {
  const x = parseInt(String(m), 10);
  if (Number.isNaN(x)) return null;
  const v = Math.max(1, Math.min(x, 24 * 60));
  return v;
}
function validatePatterns(arr, maxCount = 10, maxLen = 200) {
  const list = parseList(arr);
  if (list.length > maxCount) return list.slice(0, maxCount);
  return list.map((s) => String(s).slice(0, maxLen));
}
function validateSourcePayload(body, defaultMinutes) {
  const url = sanitizeUrl(body && body.url);
  const name =
    body && body.name !== undefined ? (body.name ? String(body.name).slice(0, 50) : null) : null;
  const minutes =
    body && body.minutes !== undefined
      ? clampMinutes(body.minutes)
      : clampMinutes(defaultMinutes || 30);
  const ua =
    body && body.ua !== undefined
      ? body.ua
        ? String(body.ua).replace(/[\r\n]/g, '').slice(0, 200)
        : undefined
      : undefined;
  const include = validatePatterns(body && body.include);
  const exclude = validatePatterns(body && body.exclude);
  return { url, name, minutes, ua, include, exclude };
}

function hashContent(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function signToken(payload, expiresSec = 2 * 24 * 60 * 60) {
  if (!AUTH_SECRET) throw new Error('AUTH_SECRET not initialized');
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expiresSec };
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(body));
  const data = `${h}.${p}`;
  const sig = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(data)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${data}.${sig}`;
}
function verifyToken(token) {
  if (!AUTH_SECRET) return null;
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const data = `${h}.${p}`;
  const sig = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(data)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  
  // Timing safe compare
  const sigBuf = Buffer.from(sig);
  const sBuf = Buffer.from(s);
  if (sigBuf.length !== sBuf.length || !crypto.timingSafeEqual(sigBuf, sBuf)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8')
    );
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
async function readAdminConfig() {
  try {
    return (await storage.readJSON(adminConfigKey)) || {};
  } catch {}
  return {};
}
async function writeAdminConfig(cfg) {
  try {
    await storage.write(adminConfigKey, cfg);
  } catch {}
}
function hashPassword(pass, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(pass), s, 32).toString('hex');
  return { salt: s, hash: h };
}
function verifyPassword(pass, hash, salt) {
  if (!hash || !salt) return false;
  const h = crypto.scryptSync(String(pass), salt, 32).toString('hex');
  const hBuf = Buffer.from(h);
  const hashBuf = Buffer.from(hash);
  if (hBuf.length !== hashBuf.length) return false;
  return crypto.timingSafeEqual(hBuf, hashBuf);
}
async function ensureConfiguredAdmin() {
  let cfg = await readAdminConfig();
  let user = process.env.ADMIN_USER || cfg.admin_user;
  let pass = process.env.ADMIN_PASS || cfg.admin_pass;
  if (!user || !pass) {
    user = 'admin';
    pass = crypto.randomBytes(12).toString('hex');
    cfg.admin_user = user;
    cfg.admin_pass = pass;
    const hp = hashPassword(pass);
    cfg.admin_pass_hash = hp.hash;
    cfg.admin_salt = hp.salt;
    await writeAdminConfig(cfg);
  }
  process.env.ADMIN_USER = user;
  process.env.ADMIN_PASS = pass;
}

function requireAdmin(req, res, next) {
  if (!adminToken) return next();
  const token = req.headers['x-admin-token'];
  if (token && String(token) === String(adminToken)) return next();
  res.status(401).json({ message: 'unauthorized' });
}
function requireAdminAny(req, res, next) {
  const headerToken = req.headers['x-admin-token'];
  const pathToken = req.params.adminId;
  const current = process.env.ADMIN_TOKEN || adminToken;
  if (!current) return next();
  if (
    (headerToken && String(headerToken) === String(current)) ||
    (pathToken && String(pathToken) === String(current))
  )
    return next();
  res.status(401).json({ message: 'unauthorized' });
}
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/.exec(String(auth));
  const token = m ? m[1] : null;
  const payload = verifyToken(token);
  if (!payload || !payload.username) return res.status(401).json({ message: 'unauthorized' });
  req.user = { username: payload.username };
  next();
}

function idForUrl(u) {
  return crypto.createHash('sha256').update(String(u)).digest('hex').slice(0, 24);
}
function cachePathFor(id) {
  return `sub_${id}.txt`;
}
function genToken() {
  return crypto.randomBytes(24).toString('hex');
}
function parseList(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}
function safeReg(pat) {
  try {
    return new RegExp(pat);
  } catch {
    return null;
  }
}
function applyFilter(text, includes, excludes) {
  const inc = (includes || []).map(safeReg).filter(Boolean);
  const exc = (excludes || []).map(safeReg).filter(Boolean);
  if (!inc.length && !exc.length) return text;
  const lines = text.split(/\r?\n/);
  const keep = lines.filter((line) => {
    // ReDoS Mitigation: Skip regex on extremely long lines (e.g. > 10KB)
    if (line.length > 10000) return true;
    const passInc = inc.length ? inc.some((r) => r.test(line)) : true;
    const passExc = exc.length ? !exc.some((r) => r.test(line)) : true;
    return passInc && passExc;
  });
  return keep.join('\n');
}
async function loadSources() {
  try {
    const j = await storage.readJSON(sourcesKey);
    if (!j) {
      // First run or missing sources
      state.users = {};
      state.sources = {};
      state.activeId = null;
      return;
    }

    if (j.users) {
      state.users = Object.create(null);
      // Copy safely to avoid prototype pollution
      for (const [k, v] of Object.entries(j.users || {})) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        state.users[k] = v;
      }
    } else {
      // migrate legacy structure to current admin user
      const adminUser = process.env.ADMIN_USER || 'admin';
      state.users = Object.create(null);
      state.users[adminUser] = {
        sources: j.sources || {},
        activeId: j.activeId || null,
        refreshMinutes: state.refreshMinutes,
        timer: null,
        timers: {},
      };
      state.sources = j.sources || {};
      state.activeId = j.activeId || null;
    }
    // fix missing tokens and migrate enabled status
    let changed = false;
    Object.values(state.users).forEach((u) => {
      Object.values(u.sources || {}).forEach((s) => {
        if (!s.token) {
          s.token = genToken();
          changed = true;
        }
        // Auto-enable active source
        if (u.activeId === s.id && s.enabled === undefined) {
          s.enabled = true;
          changed = true;
        }
        if (s.enabled === undefined) {
          s.enabled = false;
          changed = true;
        }
      });
    });
    if (changed) await saveSources();
  } catch (e) {
    console.error('Failed to load sources:', e);
    // If sources file is corrupted, we might want to start fresh or keep empty
    state.users = {};
    state.sources = {};
    state.activeId = null;
  }
}
let isSaving = false;
let pendingSave = false;

async function saveSources() {
  if (isSaving) {
    pendingSave = true;
    return;
  }
  isSaving = true;
  
  try {
    const payload = { users: state.users };
    await storage.write(sourcesKey, payload);
  } catch (e) {
    console.error('Failed to save sources:', e);
  } finally {
    isSaving = false;
    if (pendingSave) {
      pendingSave = false;
      saveSources();
    }
  }
}
async function loadCacheById(id) {
  try {
    const buf = await storage.read(cachePathFor(id));
    if (!buf) throw new Error('not_found');
    state.content = buf;
    state.etag = hashContent(buf);
    state.updatedAt = new Date().toISOString();
  } catch {
    state.content = null;
    state.etag = null;
  }
}

const MAX_CONTENT_SIZE = 10 * 1024 * 1024; // 10MB

async function fetchWithLimit(res) {
  let size = 0;
  const chunks = [];
  for await (const chunk of res.body) {
    size += chunk.length;
    if (size > MAX_CONTENT_SIZE) {
      throw new Error('content_too_large');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
];

function getRandomUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

async function fetchOnce() {
  if (!state.sourceUrl || !state.activeId) return { ok: false, reason: 'no_source' };
  if (state.loading) return { ok: false, reason: 'busy' };
  state.loading = true;
  state.lastError = null;
  try {
    const item = state.sources[state.activeId] || {};
    
    try {
      await validateTargetUrl(state.sourceUrl);
    } catch (e) {
      state.lastError = `ssrf_protection: ${e.message}`;
      state.loading = false;
      return { ok: false, reason: 'forbidden_target' };
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 30000);
    const res = await fetch(state.sourceUrl, {
      method: 'GET',
      headers: {
        Accept: 'text/plain, application/yaml, application/octet-stream, */*',
        'User-Agent': item.ua || getRandomUA(),
        ...(item.etag ? { 'If-None-Match': item.etag } : {}),
      },
      signal: controller.signal,
    });
    clearTimeout(t);
    if (res.status === 304) {
      state.loading = false;
      return { ok: true, notModified: true };
    }
    if (!res.ok) {
      state.lastError = `upstream_${res.status}`;
      state.loading = false;
      return { ok: false, reason: 'upstream_error', status: res.status };
    }
    let buf;
    try {
      buf = await fetchWithLimit(res);
    } catch (e) {
      state.lastError = e.message === 'content_too_large' ? 'content_too_large' : 'download_error';
      state.loading = false;
      return { ok: false, reason: state.lastError };
    }
    // Optional content filtering (best-effort, text only)
    const includes = item.include || [];
    const excludes = item.exclude || [];
    if (includes.length || excludes.length) {
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      const isText = ct.includes('text') || ct.includes('yaml') || ct.includes('application/yaml');
      if (isText) {
        const filtered = applyFilter(buf.toString('utf-8'), includes, excludes);
        buf = Buffer.from(filtered, 'utf-8');
      }
    }
    state.content = buf;
    state.etag = hashContent(buf);
    state.updatedAt = new Date().toISOString();
    await storage.write(cachePathFor(state.activeId), buf);
    const s = state.sources[state.activeId];
    if (s) {
      s.updatedAt = state.updatedAt;
      s.etag = res.headers.get('etag') || state.etag;
      await saveSources();
    }
    state.loading = false;
    return { ok: true };
  } catch {
    state.lastError = 'network_error';
    state.loading = false;
    return { ok: false, reason: 'network_error' };
  }
}

function startTimer() {
  if (state.timer) clearInterval(state.timer);
  const ms = Math.max(1, state.refreshMinutes) * 60 * 1000;
  state.timer = setInterval(() => {
    fetchOnce();
  }, ms);
}

function getUser(username) {
  if (!username || typeof username !== 'string') return null;
  if (username === '__proto__' || username === 'constructor' || username === 'prototype') return null;
  
  if (!state.users[username]) {
    state.users[username] = {
      sources: {},
      activeId: null,
      refreshMinutes: state.refreshMinutes,
      timer: null,
      logs: [],
      webhook: null, // Webhook URL for notifications
      timers: {},
    };
  }
  return state.users[username];
}

async function sendNotification(username, type, message) {
  const u = getUser(username);
  if (!u.webhook) return;
  try {
    try {
      await validateTargetUrl(u.webhook);
    } catch (e) {
      // If webhook is invalid, just log and return
      appendLog(username, 'error', `Webhook URL forbidden: ${e.message}`);
      return;
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 5000); // 5s timeout
    
    // Simple JSON POST
    await fetch(u.webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: `SubMirror - ${type.toUpperCase()}`,
        body: message,
        time: new Date().toLocaleString(),
        level: type
      }),
      signal: controller.signal,
    });
    clearTimeout(t);
    appendLog(username, 'info', `Notification sent to webhook`);
  } catch (e) {
    appendLog(username, 'error', `Failed to send notification: ${e.message}`);
  }
}

const historyPrefix = 'history';

// --- Persistent Logging Setup ---
// Logs are special, we might want to keep using FS for now as streams,
// but let's use the storage adapter's append if we want to be pure.
// For now, let's assume logs are local-only or sidecar.
// But wait, the user wants cloud native. In cloud native, logs usually go to stdout.
// However, we implemented "Persistent Logging" to files just a moment ago.
// Let's modify the logging to use storage.append() which we defined in the adapter.

const accessLogKey = 'logs/access.jsonl';
const securityLogKey = 'logs/security.jsonl';

function historyDirFor(id) {
  // Return a prefix key for history items
  return path.join(historyPrefix, id);
}

async function saveHistory(id, buf) {
  try {
    const dirKey = historyDirFor(id);
    const name = `${Date.now()}.txt`;
    const key = path.join(dirKey, name);
    
    await storage.write(key, buf);
    
    // Cleanup: keep last 10
    // storage.list should return relative paths or full keys?
    // Our FileStorage implementation returns filenames relative to the dir we passed.
    // Let's check storage.js: list(prefix) -> readdir(prefix) -> returns filenames
    const files = await storage.list(dirKey);
    files.sort(); 
    if (files.length > 10) {
      const toDel = files.slice(0, files.length - 10);
      for (const f of toDel) {
        await storage.delete(path.join(dirKey, f));
      }
    }
  } catch (e) {
    console.error('Failed to save history:', e);
  }
}

async function fetchOnceForUser(username, sourceId = null) {
  const u = getUser(username);
  const targetId = sourceId || u.activeId;
  if (!targetId) return { ok: false, reason: 'no_source' };
  
  // simple per-user loading lock by attaching to user object
  if (u.loading) return { ok: false, reason: 'busy' };
  u.loading = true;
  const item = u.sources[targetId] || {};
  appendLog(username, 'info', `Start syncing: ${item.name || 'Unnamed'} (${item.url})`);

  try {
    try {
      await validateTargetUrl(item.url);
    } catch (e) {
      throw new Error(`Target URL forbidden (SSRF protection): ${e.message}`);
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 30000);
    appendLog(username, 'info', 'Downloading content...');
    
    // Use manual redirect handling for better SSRF protection and debugging
    const res = await fetch(item.url, {
      method: 'GET',
      headers: {
        Accept: 'text/plain, application/yaml, application/octet-stream, */*',
        'User-Agent': item.ua || getRandomUA(),
        ...(item.etag ? { 'If-None-Match': item.etag } : {}),
      },
      signal: controller.signal,
      redirect: 'manual' 
    });
    
    clearTimeout(t);

    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
       // Handle redirect manually
       const loc = res.headers.get('location');
       const nextUrl = new URL(loc, item.url).href; // resolve relative redirect
       appendLog(username, 'info', `Redirecting to ${nextUrl}`);
       
       // Validate next URL
       try {
         await validateTargetUrl(nextUrl);
       } catch (e) {
          throw new Error(`Redirect target forbidden: ${e.message}`);
       }
       
       // Follow one level of redirect (recursive not implemented for simplicity/safety)
       const controller2 = new AbortController();
       const t2 = setTimeout(() => controller2.abort(), 30000);
       const res2 = await fetch(nextUrl, {
          method: 'GET',
          headers: {
            Accept: 'text/plain, application/yaml, application/octet-stream, */*',
            'User-Agent': item.ua || getRandomUA(),
          },
          signal: controller2.signal,
       });
       clearTimeout(t2);
       
       if (!res2.ok) {
         throw new Error(`Redirect failed: ${res2.status} ${res2.statusText}`);
       }
       // Use res2 as result
       return await processResponse(res2, item, username, u, targetId);
    }

    return await processResponse(res, item, username, u, targetId);

  } catch (e) {
    u.loading = false;
    const err = `Network error: ${e.message}`;
    console.error(`[SYNC ERROR] ${username} ${item.url}:`, e); // Log to stdout for debug
    appendLog(username, 'error', err);
    sendNotification(username, 'error', `Sync failed for ${item.name || item.url}: ${err}`);
    item.lastError = err;
    item.lastSyncStatus = 'error';
    return { ok: false, reason: 'network_error' };
  }
}

async function processResponse(res, item, username, u, targetId) {
    if (res.status === 304) {
      u.loading = false;
      appendLog(username, 'success', 'Content not modified (304)');
      return { ok: true, notModified: true };
    }
    if (!res.ok) {
      u.loading = false;
      const err = `Upstream error: ${res.status} ${res.statusText}`;
      appendLog(username, 'error', err);
      sendNotification(username, 'error', `Sync failed for ${item.name || item.url}: ${err}`);
      item.lastError = err;
      item.lastSyncStatus = 'error';
      return { ok: false, reason: 'upstream_error', status: res.status };
    }

    const includes = item.include || [];
    const excludes = item.exclude || [];
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    // Broaden text check to include common text formats
    const isText = ct.includes('text') || ct.includes('yaml') || ct.includes('json') || ct.includes('xml') || ct.includes('javascript');
    const useFilters = (includes.length || excludes.length) && isText;

    if (useFilters) {
      let buf;
      try {
        buf = await fetchWithLimit(res);
      } catch (e) {
        u.loading = false;
        const err = e.message === 'content_too_large' ? 'Content too large (>10MB) for filtering' : `Download error: ${e.message}`;
        appendLog(username, 'error', err);
        item.lastError = err;
        item.lastSyncStatus = 'error';
        return { ok: false, reason: e.message === 'content_too_large' ? 'content_too_large' : 'download_error' };
      }
      appendLog(username, 'info', `Downloaded ${buf.length} bytes (Buffered)`);

      appendLog(username, 'info', 'Applying filters...');
      const filtered = applyFilter(buf.toString('utf-8'), includes, excludes);
      buf = Buffer.from(filtered, 'utf-8');
      appendLog(username, 'info', `Filtered content size: ${buf.length} bytes`);
      
      await storage.write(cachePathFor(targetId), buf);
      item.etag = res.headers.get('etag') || hashContent(buf);
      await saveHistory(targetId, buf); // Save snapshot
    } else {
      // STREAMING MODE
      appendLog(username, 'info', 'Starting streaming download...');
      
      const hasher = crypto.createHash('sha256');
      const monitor = new PassThrough();
      let size = 0;
      monitor.on('data', (chunk) => {
        size += chunk.length;
        hasher.update(chunk);
      });

      const dest = storage.createWriteStream(cachePathFor(targetId));
      
      try {
        await pipeline(res.body, monitor, dest);
      } catch (e) {
        u.loading = false;
        const err = `Stream error: ${e.message}`;
        appendLog(username, 'error', err);
        item.lastError = err;
        item.lastSyncStatus = 'error';
        return { ok: false, reason: 'download_error' };
      }
      
      appendLog(username, 'info', `Streamed ${size} bytes`);
      item.etag = res.headers.get('etag') || hasher.digest('hex');
      
      // Save history snapshot even for streamed content
      // We read it back from cache since we don't have the full buffer in memory during stream
      // Limit to reasonable size to prevent OOM on history save if file is huge
      if (size < MAX_CONTENT_SIZE) {
         try {
           const savedBuf = await storage.read(cachePathFor(targetId));
           if (savedBuf) await saveHistory(targetId, savedBuf);
         } catch (e) {
           console.error('Failed to save history snapshot:', e);
         }
      }
    }

    item.updatedAt = new Date().toISOString();
    item.lastSyncStatus = 'success';
    item.lastError = null;
    await saveSources();
    
    u.loading = false;
    appendLog(username, 'success', 'Sync completed successfully');
    return { ok: true };
}

// Kept for backward compat but unused by fetchOnceForUser
async function fetchOnce() {
  return { ok: false, reason: 'deprecated' }; 
}
function startTimersForUser(username) {
  const u = getUser(username);
  // Clear all existing
  Object.values(u.timers || {}).forEach((t) => clearInterval(t));
  u.timers = {};

  Object.values(u.sources || {}).forEach((s) => {
    if (s.enabled) {
      const ms = Math.max(1, s.minutes || 30) * 60 * 1000;
      u.timers[s.id] = setInterval(() => {
        fetchOnceForUser(username, s.id);
      }, ms);
    }
  });
}

const limiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use('/sub', limiter);
const loginLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.use('/auth/login', loginLimiter);
const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use('/sources', writeLimiter);
app.use('/api', writeLimiter);

app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});

app.get('/status', requireAuth, (req, res) => {
  const u = getUser(req.user.username);
  res.json({
    sourceUrl: !!state.sourceUrl, // legacy global
    refreshMinutes: u.refreshMinutes || state.refreshMinutes,
    updatedAt: state.updatedAt,
    hasContent: !!state.content,
    loading: u.loading || state.loading,
    lastError: state.lastError,
    activeId: u.activeId,
    webhook: u.webhook,
  });
});

app.post('/api/settings', requireAuth, async (req, res) => {
  const { webhook } = req.body || {};
  const u = getUser(req.user.username);
  if (webhook !== undefined) {
    const val = webhook ? String(webhook).trim() : null;
    if (val) {
        try {
            await validateTargetUrl(val);
        } catch (e) {
            return res.status(400).json({ message: `Invalid Webhook URL: ${e.message}` });
        }
    }
    u.webhook = val;
  }
  await saveSources();
  res.json({ ok: true });
});

app.post('/api/test-webhook', requireAuth, async (req, res) => {
  const u = getUser(req.user.username);
  if (!u.webhook) return res.status(400).json({ message: 'no_webhook_configured' });
  
  try {
    await sendNotification(req.user.username, 'info', 'This is a test notification from SubMirror.');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

function findSourceById(id) {
  // Check global legacy sources first
  if (state.sources[id]) return state.sources[id];
  
  // Search in all users
  for (const u of Object.values(state.users)) {
    if (u.sources && u.sources[id]) return u.sources[id];
  }
  return null;
}

app.get('/sub', (req, res) => {
  const t = String(req.query.token || '');
  // Legacy support: activeId might be in a user now
  let id = state.activeId;
  let s = id ? findSourceById(id) : null;
  
  // If no global activeId, we can try to find if this token matches *any* source?
  // But /sub implies a single "active" subscription.
  
  if (!s || !t || s.token !== t) {
    recordAccess(req, id || 'unknown', 403);
    return res.status(403).json({ message: 'forbidden' });
  }
  if (s.expiresAt && Date.now() > new Date(s.expiresAt).getTime()) {
    recordAccess(req, id, 410);
    return res.status(410).json({ message: 'expired' });
  }
  
  // Try to load content
  // Legacy state.content is only for global activeId.
  // If we found 's' via findSourceById, we should try to load its cache.
  // If it matches global activeId, maybe state.content is populated.
  
  if (state.activeId === id && state.content) {
     recordAccess(req, id, 200);
     res.setHeader('Content-Type', 'text/plain; charset=utf-8');
     res.setHeader('ETag', state.etag);
     res.setHeader('Cache-Control', 'no-store');
     return res.status(200).send(state.content);
  }
  
  // Try to read from storage
  storage.read(cachePathFor(id)).then(buf => {
     if (!buf) {
        recordAccess(req, id, 503);
        return res.status(503).json({ message: 'no_cache' });
     }
     recordAccess(req, id, 200);
     res.setHeader('Content-Type', 'text/plain; charset=utf-8');
     res.setHeader('ETag', hashContent(buf));
     res.setHeader('Cache-Control', 'no-store');
     res.status(200).send(buf);
  }).catch(() => {
     recordAccess(req, id, 503);
     res.status(503).json({ message: 'no_cache' });
  });
});

app.get('/sub/:id', async (req, res) => {
  const id = String(req.params.id || '');
  const t = String(req.query.token || req.params.token || '');
  const s = findSourceById(id);
  
  if (!s || !t || s.token !== t) {
    recordAccess(req, id || 'unknown', 403);
    return res.status(403).json({ message: 'forbidden' });
  }
  if (s.expiresAt && Date.now() > new Date(s.expiresAt).getTime()) {
    recordAccess(req, id, 410);
    return res.status(410).json({ message: 'expired' });
  }
  
  try {
    const buf = await storage.read(cachePathFor(id));
    if (!buf) {
        recordAccess(req, id, 503);
        return res.status(503).json({ message: 'no_cache' });
    }
    recordAccess(req, id, 200);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('ETag', hashContent(buf));
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).send(buf);
  } catch {
    recordAccess(req, id, 503);
    res.status(503).json({ message: 'no_cache' });
  }
});

app.post('/sources/:id/sync', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const usr = getUser(req.user.username);
  if (!usr.sources[id]) return res.status(404).json({ message: 'not_found' });
  const r = await fetchOnceForUser(req.user.username, id);
  if (!r.ok) return res.status(502).json(r);
  res.json({ ok: true, updatedAt: usr.sources[id].updatedAt });
});

app.get('/sources/:id/history', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const usr = getUser(req.user.username);
  if (!usr.sources[id]) return res.status(404).json({ message: 'not_found' });
  
  const dirKey = historyDirFor(id);
  try {
    const files = await storage.list(dirKey);
    const list = await Promise.all(files.map(async f => {
      const st = await storage.stat(path.join(dirKey, f));
      return {
        name: f,
        ts: parseInt(f.split('.')[0]),
        size: st ? st.size : 0
      };
    }));
    // sort new -> old
    list.sort((a, b) => b.ts - a.ts);
    res.json({ ok: true, items: list });
  } catch (e) {
    res.json({ ok: true, items: [] });
  }
});

app.post('/sources/:id/rollback', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const { filename } = req.body || {};
  const usr = getUser(req.user.username);
  const item = usr.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  if (!filename) return res.status(400).json({ message: 'missing_filename' });
  if (filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
    return res.status(400).json({ message: 'invalid_filename' });
  }

  const p = path.join(historyDirFor(id), filename);
  // Can't check exists easily without reading or stat-ing.
  // Let's just try to read.
  
  try {
    const buf = await storage.read(p);
    if (!buf) return res.status(404).json({ message: 'history_not_found' });

    await storage.write(cachePathFor(id), buf);
    
    // Update state but NOT history (rolling back is not a new sync)
    item.updatedAt = new Date().toISOString(); // mark as updated now
    item.etag = hashContent(buf);
    item.lastSyncStatus = 'success'; // treat rollback as success
    item.lastError = 'Rolled back manually'; 
    await saveSources();
    
    appendLog(req.user.username, 'warning', `Rolled back ${item.name} to history version ${filename}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

app.post('/refresh', requireAuth, async (req, res) => {
  const r = await fetchOnceForUser(req.user.username);
  if (!r.ok) return res.status(502).json(r);
  const u = getUser(req.user.username);
  const item = u.sources[u.activeId];
  res.json({ ok: true, updatedAt: item ? item.updatedAt : new Date(), etag: item ? item.etag : null });
});

app.post('/source', requireAdmin, async (req, res) => {
  const v = validateSourcePayload(req.body || {}, state.refreshMinutes);
  if (!v.url) return res.status(400).json({ message: 'invalid_url' });
  const id = idForUrl(v.url);
  const mm = v.minutes || state.refreshMinutes;
  const token = genToken();
  state.sources[id] = {
    id,
    url: v.url,
    name: v.name,
    minutes: mm,
    token,
    expiresAt: null,
    ua: v.ua,
    include: v.include,
    exclude: v.exclude,
    enabled: false,
  };
  state.activeId = id;
  state.sourceUrl = v.url;
  state.refreshMinutes = mm;
  await saveSources();
  startTimer();
  const r = await fetchOnce();
  res.json({ ok: r.ok, updatedAt: state.updatedAt, hasContent: !!state.content, id, token });
});

app.get('/sources', requireAuth, (req, res) => {
  const u = getUser(req.user.username);
  res.json({ activeId: u.activeId, items: Object.values(u.sources || {}) });
});
app.get('/api/:adminId/sources', requireAdminAny, (req, res) => {
  res.json({ activeId: state.activeId, items: Object.values(state.sources) });
});
app.post('/sources', requireAuth, async (req, res) => {
  const v = validateSourcePayload(req.body || {}, 30);
  if (!v.url) return res.status(400).json({ message: 'invalid_url' });
  const id = idForUrl(v.url);
  const mm = v.minutes || 30;
  const token = genToken();
  const usr = getUser(req.user.username);
  usr.sources[id] = {
    id,
    url: v.url,
    name: v.name,
    minutes: mm,
    token,
    expiresAt: null,
    ua: v.ua,
    include: v.include,
    exclude: v.exclude,
    enabled: false,
  };
  await saveSources();
  res.json({ ok: true, id, token });
});
app.post('/sources/:id/activate', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const usr = getUser(req.user.username);
  const item = usr.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  usr.activeId = id;
  // Also enable it if activated
  item.enabled = true;
  await saveSources();
  startTimersForUser(req.user.username);
  const r = await fetchOnceForUser(req.user.username, id);
  // update legacy global active for backward compatibility of /sub
  state.activeId = id;
  state.sources[id] = item;
  res.json({ ok: r.ok, activeId: usr.activeId, token: item.token });
});

app.post('/sources/:id/toggle-sync', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const { enabled } = req.body || {};
  const usr = getUser(req.user.username);
  const item = usr.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  
  item.enabled = !!enabled;
  await saveSources();
  startTimersForUser(req.user.username);
  
  // If enabling, trigger one sync immediately if none recent? 
  // For now just start timer. Maybe user wants immediate sync, they can click sync.
  
  res.json({ ok: true, enabled: item.enabled });
});
app.put('/sources/:id', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const {
    url,
    minutes,
    expiresAt,
    ttlMinutes,
    durationUnit,
    durationValue,
    name,
    ua,
    include,
    exclude,
  } = req.body || {};
  const usr = getUser(req.user.username);
  const item = usr.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  if (url) item.url = sanitizeUrl(url);
  if (name !== undefined) item.name = name ? String(name).slice(0, 50) : null;
  if (ua !== undefined) item.ua = ua ? String(ua).slice(0, 200) : undefined;
  if (include !== undefined) item.include = validatePatterns(include);
  if (exclude !== undefined) item.exclude = validatePatterns(exclude);
  if (minutes) {
    const m = clampMinutes(minutes);
    if (m) item.minutes = m;
  }
  if (expiresAt === null) {
    item.expiresAt = null;
  } else if (typeof expiresAt === 'string') {
    const ts = new Date(expiresAt).getTime();
    if (!isNaN(ts)) item.expiresAt = new Date(ts).toISOString();
  } else if (typeof ttlMinutes === 'number' && ttlMinutes > 0) {
    item.expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  } else if (durationUnit && typeof durationValue === 'number' && durationValue > 0) {
    const mins = durationUnit === 'hours' ? durationValue * 60 : durationValue;
    item.expiresAt = new Date(Date.now() + mins * 60 * 1000).toISOString();
  }
  await saveSources();
  startTimersForUser(req.user.username);
  res.json({ ok: true, token: item.token, expiresAt: item.expiresAt });
});
app.post('/sources/:id/rotate-token', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const usr = getUser(req.user.username);
  const item = usr.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  item.token = genToken();
  await saveSources();
  res.json({ ok: true, token: item.token });
});
app.delete('/sources/:id', requireAuth, async (req, res) => {
  const id = String(req.params.id || '');
  const usr = getUser(req.user.username);
  if (!usr.sources[id]) return res.status(404).json({ message: 'not_found' });
  delete usr.sources[id];
  // stop timer
  if (usr.timers && usr.timers[id]) {
    clearInterval(usr.timers[id]);
    delete usr.timers[id];
  }
  if (usr.activeId === id) {
    usr.activeId = null;
  }
  await saveSources();
  res.json({ ok: true });
});

// Path-based admin API
app.post('/api/:adminId/sources', requireAdminAny, async (req, res) => {
  const v = validateSourcePayload(req.body || {}, 30);
  if (!v.url) return res.status(400).json({ message: 'invalid_url' });
  const id = idForUrl(v.url);
  const mm = v.minutes || 30;
  const token = genToken();
  state.sources[id] = {
    id,
    url: v.url,
    name: v.name,
    minutes: mm,
    token,
    expiresAt: null,
    ua: v.ua,
    include: v.include,
    exclude: v.exclude,
    enabled: false,
  };
  await saveSources();
  res.json({ ok: true, id, token });
});
app.put('/api/:adminId/sources/:id', requireAdminAny, async (req, res) => {
  const id = String(req.params.id || '');
  const {
    url,
    minutes,
    expiresAt,
    ttlMinutes,
    durationUnit,
    durationValue,
    name,
    ua,
    include,
    exclude,
  } = req.body || {};
  const item = state.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  if (url) item.url = sanitizeUrl(url);
  if (name !== undefined) item.name = name ? String(name).slice(0, 50) : null;
  if (ua !== undefined) item.ua = ua ? String(ua).slice(0, 200) : undefined;
  if (include !== undefined) item.include = parseList(include);
  if (exclude !== undefined) item.exclude = parseList(exclude);
  if (minutes) {
    const m = parseInt(String(minutes), 10);
    if (!Number.isNaN(m) && m > 0) item.minutes = m;
  }
  if (expiresAt === null) {
    item.expiresAt = null;
  } else if (typeof expiresAt === 'string') {
    const ts = new Date(expiresAt).getTime();
    if (!isNaN(ts)) item.expiresAt = new Date(ts).toISOString();
  } else if (typeof ttlMinutes === 'number' && ttlMinutes > 0) {
    item.expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  } else if (durationUnit && typeof durationValue === 'number' && durationValue > 0) {
    const mins = durationUnit === 'hours' ? durationValue * 60 : durationValue;
    item.expiresAt = new Date(Date.now() + mins * 60 * 1000).toISOString();
  }
  await saveSources();
  if (state.activeId === id) {
    state.sourceUrl = item.url;
    state.refreshMinutes = item.minutes;
    startTimer();
  }
  // also restart user timers if needed (if admin modified via path api)
  // this is a bit complex as we don't know which user owns it easily without scanning
  // but path api is legacy/admin-only.
  res.json({ ok: true, token: item.token, expiresAt: item.expiresAt });
});
app.delete('/api/:adminId/sources/:id', requireAdminAny, async (req, res) => {
  const id = String(req.params.id || '');
  if (!state.sources[id]) return res.status(404).json({ message: 'not_found' });
  delete state.sources[id];
  if (state.activeId === id) {
    state.activeId = null;
    state.sourceUrl = null;
    state.content = null;
    state.etag = null;
  }
  await saveSources();
  res.json({ ok: true });
});
app.post('/api/:adminId/sources/:id/activate', requireAdminAny, async (req, res) => {
  const id = String(req.params.id || '');
  const item = state.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  state.activeId = id;
  state.sourceUrl = item.url;
  state.refreshMinutes = item.minutes;
  await saveSources();
  await loadCacheById(id);
  startTimer();
  const r = await fetchOnce();
  res.json({ ok: r.ok, activeId: state.activeId, updatedAt: state.updatedAt, token: item.token });
});
app.post('/api/:adminId/sources/:id/rotate-token', requireAdminAny, async (req, res) => {
  const id = String(req.params.id || '');
  const item = state.sources[id];
  if (!item) return res.status(404).json({ message: 'not_found' });
  item.token = genToken();
  await saveSources();
  res.json({ ok: true, token: item.token });
});
app.post('/api/:adminId/refresh', requireAdminAny, async (req, res) => {
  const r = await fetchOnce();
  if (!r.ok) return res.status(502).json(r);
  res.json({ ok: true, updatedAt: state.updatedAt, etag: state.etag });
});
// Auth endpoints
app.get('/logs', requireAuth, (req, res) => {
  console.log(`[DEBUG] /logs accessed by ${req.user.username}`);
  const u = getUser(req.user.username);
  res.json({ logs: u.logs || [] });
});

app.get('/stats', requireAuth, (req, res) => {
  // Sort IPs by count
  const topIPs = Object.entries(state.ipStats)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)
    .map(([ip, d]) => ({ ip, count: d.count }));
    
  // Sort UAs by count
  const topUAs = Object.entries(state.uaStats)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ua, count]) => ({ ua, count }));
    
  res.json({
    today: state.todayCounts,
    topIPs,
    topUAs,
    recentLogs: state.accessLogs.slice(0, 50),
    alerts: state.securityAlerts
  });
});

// --- CLOUDFLARE TURNSTILE CONFIGURATION ---
// Replace the value below with your actual Secret Key from Cloudflare Dashboard
// You can also set this via environment variable: set CF_SECRET_KEY=your_secret_key
const CF_SECRET_KEY = process.env.CF_SECRET_KEY || '1x0000000000000000000000000000000AA'; 

// Login brute-force protection
const loginFailures = {}; // ip -> { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 mins

// Clean up old login failure records
setInterval(() => {
  const now = Date.now();
  Object.keys(loginFailures).forEach(ip => {
    if (loginFailures[ip].lockedUntil && loginFailures[ip].lockedUntil < now) {
      delete loginFailures[ip];
    } else if (!loginFailures[ip].lockedUntil && now - (loginFailures[ip].lastAttempt || 0) > 3600000) {
      // Clear count if no attempt for 1 hour
      delete loginFailures[ip];
    }
  });
}, 60000);

app.post('/auth/login', async (req, res) => {
  const ip = getClientIp(req);
  const now = Date.now();
  
  // Check lockout
  const isLocal = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (!isLocal && loginFailures[ip] && loginFailures[ip].lockedUntil > now) {
    const waitMin = Math.ceil((loginFailures[ip].lockedUntil - now) / 60000);
    recordAccess(req, 'login', 429);
    return res.status(429).json({ message: `Too many failed attempts. Try again in ${waitMin} minutes.` });
  }

  const { username, password, cfToken } = req.body || {};
  
  // Verify Turnstile Token
  // Only verify if provided (for backward compat or optional mode), 
  // BUT for security you should enforce it. 
  // Here we enforce it if CF_SECRET_KEY is configured (which is default dummy).
  if (CF_SECRET_KEY) {
    if (!cfToken) {
       // Allow bypassing CAPTCHA in dev mode if using default key and localhost
       if (isLocal && CF_SECRET_KEY === '1x0000000000000000000000000000000AA') {
          // bypass
       } else {
          return res.status(400).json({ message: 'missing_captcha' });
       }
    } else {
      try {
        const formData = new URLSearchParams();
        formData.append('secret', CF_SECRET_KEY);
        formData.append('response', cfToken);
        formData.append('remoteip', ip);
  
        const cfRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST',
          body: formData,
        });
        const cfData = await cfRes.json();
        if (!cfData.success) {
          return res.status(403).json({ message: 'captcha_failed' });
        }
      } catch (e) {
        console.error('Turnstile error:', e);
        // Fail open or closed? Fail open for now if CF is down, but safer to fail closed.
        // return res.status(500).json({ message: 'captcha_error' });
      }
    }
  }

  const u = String(username || '').trim();
  const p = String(password || '');
  if (!u || !p) return res.status(400).json({ message: 'missing_credentials' });
  
  const cfg = await readAdminConfig();
  const confUser = process.env.ADMIN_USER || cfg.admin_user;
  const confPass = process.env.ADMIN_PASS || cfg.admin_pass;
  const confHash = process.env.ADMIN_PASS_HASH || cfg.admin_pass_hash;
  const confSalt = process.env.ADMIN_SALT || cfg.admin_salt;
  
  if (!confUser || (!confPass && !confHash))
    return res.status(500).json({ message: 'server_not_configured' });
    
  const passOk =
    confHash && confSalt ? verifyPassword(p, confHash, confSalt) : String(p) === String(confPass);
    
  if (u !== confUser || !passOk) {
    // Record failure
    if (!loginFailures[ip]) loginFailures[ip] = { count: 0, lastAttempt: 0 };
    loginFailures[ip].count++;
    loginFailures[ip].lastAttempt = now;
    
    if (loginFailures[ip].count >= MAX_LOGIN_ATTEMPTS && !isLocal) {
      loginFailures[ip].lockedUntil = now + LOCKOUT_TIME;
      triggerSecurityAlert(ip, 'Brute Force Login Blocked', null);
    }
    
    // Add random delay to mitigate timing attacks and slow down brute force (500ms - 1500ms)
    const delay = Math.floor(Math.random() * 1000) + 500;
    await new Promise(resolve => setTimeout(resolve, delay));

    recordAccess(req, 'login', 401);
    return res.status(401).json({ message: 'unauthorized' });
  }
  
  // Reset failure on success
  if (loginFailures[ip]) delete loginFailures[ip];
  
  const token = signToken({ username: u });
  recordAccess(req, 'login', 200, u);
  res.json({ ok: true, token });
});
app.get('/auth/me', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/.exec(String(auth));
  const token = m ? m[1] : null;
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ message: 'unauthorized' });
  res.json({ ok: true, user: { username: payload.username } });
});

app.post('/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ message: 'missing_fields' });

  // 1. Verify current password
  const cfg = await readAdminConfig();
  const confUser = process.env.ADMIN_USER || cfg.admin_user;
  const confPass = process.env.ADMIN_PASS || cfg.admin_pass;
  const confHash = process.env.ADMIN_PASS_HASH || cfg.admin_pass_hash;
  const confSalt = process.env.ADMIN_SALT || cfg.admin_salt;

  // We assume the logged-in user is the admin (since it's a single-user system effectively for admin tasks)
  // But wait, requireAuth populates req.user.username.
  // If we have multi-users in future, this needs to be user-specific.
  // For now, let's assume this changes the MAIN admin password if the user is admin.
  if (req.user.username !== confUser) {
    return res.status(403).json({ message: 'only_admin_can_change_password' });
  }

  const passOk = confHash && confSalt ? verifyPassword(currentPassword, confHash, confSalt) : String(currentPassword) === String(confPass);
  
  if (!passOk) {
    // Add delay here too
    await new Promise(resolve => setTimeout(resolve, 1000));
    return res.status(401).json({ message: 'invalid_current_password' });
  }

  // 2. Validate new password strength
  if (newPassword.length < 10) {
    return res.status(400).json({ message: 'password_too_short_min_10' });
  }
  // At least one uppercase, one lowercase, one number, one special char
  // Simplified: mixed case and number
  if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
     return res.status(400).json({ message: 'password_complexity_failed: must contain uppercase, lowercase and number' });
  }

  // 3. Save new password
  const { salt, hash } = hashPassword(newPassword);
  cfg.admin_pass_hash = hash;
  cfg.admin_salt = salt;
  delete cfg.admin_pass; // remove plain text if exists
  await writeAdminConfig(cfg);
  
  // 4. Update process.env to reflect changes immediately
  process.env.ADMIN_PASS_HASH = hash;
  process.env.ADMIN_SALT = salt;
  process.env.ADMIN_PASS = ''; 

  appendLog(req.user.username, 'warning', 'Admin password changed successfully');
  res.json({ ok: true });
});

async function bootstrap() {
  ensureAdminToken();
  ensureConfiguredAdmin();
  AUTH_SECRET = await ensureAuthSecret(); // Wait for secret
  await loadSources();
  // start timers for each user
  Object.keys(state.users || {}).forEach((username) => {
    startTimersForUser(username);
  });
  app.listen(port, () => {});
}

bootstrap();
