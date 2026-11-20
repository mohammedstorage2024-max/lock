require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const IS_VERCEL = process.env.VERCEL === '1';
// Netlify bundles the function under netlify/functions while included_files
// may be rooted at the Lambda task directory (/var/task).
const VIEWS_DIR = [
  process.env.LAMBDA_TASK_ROOT && path.join(process.env.LAMBDA_TASK_ROOT, 'views'),
  path.join(ROOT, 'views'),
].filter(Boolean).find((directory) => fs.existsSync(directory)) || path.join(ROOT, 'views');
// Vercel's deployed function bundle is read-only. Its /tmp directory is
// writable, but ephemeral; durable Vercel storage needs an external store.
const DATA_DIR = IS_VERCEL ? path.join('/tmp', 'stillroom-vault') : path.join(ROOT, 'storage');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'vault.json');
// Netlify's build flag is not guaranteed to be present in every Functions
// runtime configuration. Lambda markers keep the function on its Blobs path
// instead of trying to create files inside the read-only deployment bundle.
const IS_NETLIFY = !IS_VERCEL && (process.env.NETLIFY === 'true'
  || Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME)
  || Boolean(process.env.LAMBDA_TASK_ROOT));
const MAX_UPLOAD_BYTES = IS_NETLIFY || IS_VERCEL ? 4 * 1024 * 1024 : 100 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.webp', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.zip']);

if (!IS_NETLIFY) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ files: [], links: [] }, null, 2));
}

const getBlobStore = (name) => {
  const { getStore } = require('@netlify/blobs');
  return getStore(name, {
    region: process.env.NETLIFY_BLOBS_REGION || 'ap-southeast-1',
  });
};

const readVault = async () => {
  if (IS_NETLIFY) {
    return (await getBlobStore('stillroom-vault-data').get('index', { type: 'json', consistency: 'strong' })) || { files: [], links: [] };
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { files: [], links: [] }; }
};

const writeVault = async (vault) => {
  if (IS_NETLIFY) return getBlobStore('stillroom-vault-data').set('index', JSON.stringify(vault));
  fs.writeFileSync(DB_FILE, JSON.stringify(vault, null, 2));
};

const safeEqual = (leftValue, rightValue) => {
  if (typeof leftValue !== 'string' || typeof rightValue !== 'string' || !leftValue.length || !rightValue.length) return false;
  const left = Buffer.from(leftValue);
  const right = Buffer.from(rightValue);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};

const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const credentialsConfigured = () => Boolean(process.env.VAULT_USERNAME && process.env.VAULT_PASSWORD && process.env.SESSION_SECRET);
const requireAuth = (req, res, next) => req.session?.authenticated ? next() : res.redirect('/login');
const encodeSession = (session) => {
  const payload = Buffer.from(JSON.stringify(session)).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'local-development-secret-change-this-before-deploying').update(payload).digest('base64url');
  return `${payload}.${signature}`;
};
const sessionCookie = (session) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  if (!session) return `stillroom.sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secure}`;
  return `stillroom.sid=${encodeSession(session)}; Path=/; Max-Age=28800; HttpOnly; SameSite=Lax${secure}`;
};
const signedCookieSession = (req, res, next) => {
  const rawCookie = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith('stillroom.sid='));
  const signed = rawCookie?.slice('stillroom.sid='.length) || '';
  const [payload, signature] = signed.split('.');
  let session = {};
  if (payload && signature) {
    const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET || 'local-development-secret-change-this-before-deploying').update(payload).digest('base64url');
    if (safeEqual(signature, expected)) {
      try { session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { session = {}; }
      if (session.expiresAt && session.expiresAt < Date.now()) session = {};
    }
  }
  req.session = session;
  const before = JSON.stringify(session);
  const originalWriteHead = res.writeHead;
  const originalEnd = res.end;
  let cookieSet = false;
  const setSessionCookie = () => {
    if (cookieSet) return;
    cookieSet = true;
    const updated = req.session === null ? null : req.session;
    if (JSON.stringify(updated) !== before || updated === null) res.setHeader('Set-Cookie', sessionCookie(updated));
  };
  res.writeHead = function (...args) { setSessionCookie(); return originalWriteHead.apply(this, args); };
  res.end = function (...args) { setSessionCookie(); return originalEnd.apply(this, args); };
  next();
};

app.set('view engine', 'ejs');
app.set('views', VIEWS_DIR);
app.locals.path = path;
app.locals.vaultUsername = process.env.VAULT_USERNAME || '';
app.locals.uploadLimit = IS_NETLIFY ? '4 MB on Netlify' : IS_VERCEL ? '4 MB on Vercel' : '100 MB';
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.static(path.join(ROOT, 'static')));
app.use(signedCookieSession);
app.use((req, res, next) => {
  if (!req.session) req.session = {};
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (req.method === 'POST' && !req.is('multipart/form-data') && !safeEqual(req.body._csrf, req.session.csrfToken)) return res.sendStatus(403);
  next();
});

const upload = multer({
  storage: IS_NETLIFY || IS_VERCEL ? multer.memoryStorage() : multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const supported = ALLOWED_EXTENSIONS.has(path.extname(file.originalname).toLowerCase());
    cb(supported ? null : new Error('That file type is not supported.'), supported);
  },
});

app.get('/login', (req, res) => {
  if (!credentialsConfigured()) return res.status(503).render('login', { error: 'Private sign-in is not configured. Set the username, password and session secret, then restart.' });
  if (req.session.authenticated) return res.redirect('/');
  res.render('login', { error: '' });
});

app.post('/login', (req, res) => {
  if (!credentialsConfigured()) return res.status(503).render('login', { error: 'Private sign-in is not configured. Set the username, password and session secret, then restart.' });
  if (!safeEqual(req.body.username, process.env.VAULT_USERNAME) || !safeEqual(req.body.password, process.env.VAULT_PASSWORD)) {
    return res.status(401).render('login', { error: 'That username or password did not match. Try again.' });
  }
  req.session = { authenticated: true, csrfToken: crypto.randomBytes(24).toString('hex'), expiresAt: Date.now() + 8 * 60 * 60 * 1000 };
  res.redirect('/');
});

app.post('/logout', requireAuth, (req, res) => {
  req.session = null;
  res.redirect('/login');
});

app.get('/', requireAuth, asyncRoute(async (req, res) => {
  const vault = await readVault();
  const query = String(req.query.q || '').trim().toLowerCase();
  const files = vault.files.filter((item) => !query || `${item.title} ${item.name} ${item.note}`.toLowerCase().includes(query));
  const links = vault.links.filter((item) => !query || `${item.title} ${item.note} ${item.url}`.toLowerCase().includes(query));
  res.render('dashboard', { files, links, query, message: req.query.message || '', error: req.query.error || '' });
}));

app.post('/files', requireAuth, (req, res, next) => upload.single('file')(req, res, (error) => {
  if (error) {
    const message = error.code === 'LIMIT_FILE_SIZE' ? `Files must be ${app.locals.uploadLimit} or smaller.` : error.message;
    return res.redirect(`/?error=${encodeURIComponent(message)}`);
  }
  if (!safeEqual(req.body?._csrf, req.session.csrfToken)) {
    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.sendStatus(403);
  }
  if (!req.file) return res.redirect('/?error=Choose%20a%20file%20to%20upload.');
  void (async () => {
    const id = crypto.randomUUID();
    const storedName = IS_NETLIFY || IS_VERCEL ? `${id}${path.extname(req.file.originalname).toLowerCase()}` : req.file.filename;
    if (IS_NETLIFY) await getBlobStore('stillroom-vault-files').set(storedName, new Blob([req.file.buffer], { type: req.file.mimetype }));
    else if (IS_VERCEL) fs.writeFileSync(path.join(UPLOAD_DIR, storedName), req.file.buffer);
    const vault = await readVault();
    vault.files.unshift({
      id,
      title: String(req.body.title || '').trim().slice(0, 160) || path.parse(req.file.originalname).name,
      name: path.basename(req.file.originalname).slice(0, 240),
      storedName,
      mimetype: req.file.mimetype,
      note: String(req.body.note || '').trim().slice(0, 500),
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
    });
    await writeVault(vault);
    res.redirect('/?message=Your%20file%20is%20safely%20in%20the%20vault.');
  })().catch(next);
}));

app.get('/files/:id/preview', requireAuth, asyncRoute(async (req, res) => {
  const file = (await readVault()).files.find((item) => item.id === req.params.id);
  if (!file) return res.sendStatus(404);
  if (path.extname(file.name).toLowerCase() !== '.pdf') return res.redirect(`/files/${encodeURIComponent(file.id)}/open`);
  res.render('preview', { file });
}));

app.get('/files/:id/open', requireAuth, asyncRoute(async (req, res) => {
  const file = (await readVault()).files.find((item) => item.id === req.params.id);
  if (!file) return res.sendStatus(404);
  res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(file.name)}`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.type(file.mimetype || 'application/octet-stream');
  if (IS_NETLIFY) {
    const data = await getBlobStore('stillroom-vault-files').get(file.storedName, { type: 'arrayBuffer', consistency: 'strong' });
    if (!data) return res.sendStatus(404);
    return res.send(Buffer.from(data));
  }
  const diskPath = path.join(UPLOAD_DIR, path.basename(file.storedName));
  if (!fs.existsSync(diskPath)) return res.sendStatus(404);
  res.sendFile(diskPath);
}));

app.post('/files/:id/delete', requireAuth, asyncRoute(async (req, res) => {
  const vault = await readVault();
  const file = vault.files.find((item) => item.id === req.params.id);
  if (!file) return res.redirect('/');
  if (IS_NETLIFY) await getBlobStore('stillroom-vault-files').delete(file.storedName);
  else {
    const diskPath = path.join(UPLOAD_DIR, path.basename(file.storedName));
    if (fs.existsSync(diskPath)) fs.unlinkSync(diskPath);
  }
  vault.files = vault.files.filter((item) => item.id !== file.id);
  await writeVault(vault);
  res.redirect('/?message=File%20removed%20from%20the%20vault.');
}));

app.post('/links', requireAuth, asyncRoute(async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 160);
  const urlText = String(req.body.url || '').trim();
  let url;
  try { url = new URL(urlText); } catch { return res.redirect('/?error=Enter%20a%20valid%20link.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !title) return res.redirect('/?error=Enter%20a%20name%20and%20a%20valid%20link.');
  const vault = await readVault();
  vault.links.unshift({ id: crypto.randomUUID(), title, url: url.href, note: String(req.body.note || '').trim().slice(0, 240), addedAt: new Date().toISOString() });
  await writeVault(vault);
  res.redirect('/?message=Drive%20shortcut%20added.');
}));

app.post('/links/:id/delete', requireAuth, asyncRoute(async (req, res) => {
  const vault = await readVault();
  vault.links = vault.links.filter((item) => item.id !== req.params.id);
  await writeVault(vault);
  res.redirect('/?message=Drive%20shortcut%20removed.');
}));

app.use((error, _req, res, _next) => {
  console.error(error.message);
  if (res.headersSent) return;
  res.status(500).send('Something went wrong. Please go back and try again.');
});

if (require.main === module) app.listen(PORT, '127.0.0.1', () => console.log(`Stillroom is ready at http://localhost:${PORT}`));
// Vercel detects server.js as the Express entry point and requires the app
// itself as the CommonJS default export.
module.exports = app;
