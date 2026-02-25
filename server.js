import express from "express";
import session from "express-session";
import helmet from "helmet";
import morgan from "morgan";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import multer from "multer";
import bcrypt from "bcryptjs";
import validator from "validator";
import nodemailer from "nodemailer";
import sanitizeHtml from "sanitize-html";
import dns from "dns/promises";

import createSqliteStore from "better-sqlite3-session-store";

import {
  db,
  DATA_DIR,
  DB_PATH,
  getSetting,
  setSetting,
  listSettings,
  getPage,
  updatePage,
  adminCount,
  getAdminByEmail,
  getAdminById,
  listAdmins,
  createAdmin,
  deactivateAdmin,
  updateAdminPassword,
  addMedia,
  listMedia,
  getMedia,
  deleteMedia
} from './src/db.js';

const app = express();
const PORT = process.env.PORT || 3000;

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- View engine ----------
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

// ---------- Middleware ----------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("combined"));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.json({ limit: "2mb" }));

// Render sits behind a reverse proxy (needed for secure cookies)
app.set("trust proxy", 1);

// Sessions persisted in SQLite
const SqliteStore = createSqliteStore(session);
const sessionStore = new SqliteStore({
  client: db,
  expired: 1000 * 60 * 60 * 24 * 14,   // 14 days
  clearInterval: 1000 * 60 * 60        // cleanup hourly
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: "auto",
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

app.use(session({
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 1000 * 60 * 60 * 6 // every 6h
    }
  }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: "auto",
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

// ---------- Helpers ----------
function currentAdmin(req) {
  const id = req.session?.adminId;
  if (!id) return null;
  return getAdminById(id);
}

function requireAdmin(req, res, next) {
  const admin = currentAdmin(req);
  if (!admin) return res.redirect('/login');
  req.admin = admin;
  next();
}

function formatPageContent(raw, settings) {
  // Replace simple placeholders
  const tokens = {
    '{coverage}': settings.coverage,
    '{address}': settings.address,
    '{phone}': settings.phone,
    '{company_name}': settings.company_name,
    '{tagline}': settings.tagline
  };
  let text = String(raw || '');
  for (const [k, v] of Object.entries(tokens)) text = text.split(k).join(String(v || ''));

  // Allow a very small subset of HTML, otherwise treat as text.
  // Admin edits are stored as plain text by default, but you can paste basic formatting.
  const cleaned = sanitizeHtml(text, {
    allowedTags: ['b', 'strong', 'i', 'em', 'u', 'br', 'p', 'ul', 'ol', 'li', 'a'],
    allowedAttributes: {
      a: ['href', 'target', 'rel']
    },
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }, true)
    }
  });

  // If no <p> tags, convert line breaks to paragraphs for nicer display
  if (!cleaned.includes('<p')) {
    const parts = cleaned
      .split(/\n\n+/)
      .map(p => p.trim())
      .filter(Boolean)
      .map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`)
      .join('\n');
    return parts || '';
  }
  return cleaned;
}

async function emailDomainHasMX(email) {
  const domain = String(email).split('@')[1];
  if (!domain) return false;
  try {
    const mx = await dns.resolveMx(domain);
    return Array.isArray(mx) && mx.length > 0;
  } catch {
    return false;
  }
}

function buildTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
  });
}

// Settings available everywhere
app.use((req, res, next) => {
  const settings = listSettings([
    'company_name', 'tagline', 'phone', 'address', 'coverage',
    'map_link', 'what3words_link', 'facebook_link', 'instagram_link', 'tiktok_link', 'youtube_link'
  ]);
  res.locals.settings = settings;
  res.locals.admin = currentAdmin(req);
  next();
});

// ---------- Routes ----------
app.get('/', (req, res) => {
  const page = getPage('home');
  const settings = res.locals.settings;
  res.render('home', {
    title: `${settings.company_name} – ${settings.tagline}`,
    pageTitle: page?.title || 'Welcome',
    contentHtml: formatPageContent(page?.content, settings)
  });
});

app.get('/gallery', (req, res) => {
  const media = listMedia();
  res.render('gallery', {
    title: 'Gallery',
    media
  });
});

// Uploads (admin only)
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const name = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`;
      cb(null, name);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 200 }, // 200MB
  fileFilter: (_req, file, cb) => {
    const okImage = file.mimetype.startsWith('image/');
    const okVideo = file.mimetype.startsWith('video/');
    if (!okImage && !okVideo) return cb(new Error('Only images or video files are allowed'));
    cb(null, true);
  }
});

app.post('/admin/upload', requireAdmin, upload.single('media'), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('No file uploaded');

  const type = file.mimetype.startsWith('video/') ? 'video' : 'image';
  const caption = String(req.body.caption || '').slice(0, 200);

  addMedia({
    type,
    filename: file.filename,
    original_name: file.originalname,
    caption,
    mime: file.mimetype,
    uploaded_by: req.admin.id
  });

  res.redirect('/gallery');
});

app.post('/admin/media/:id/delete', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const item = getMedia(id);
  if (!item) return res.redirect('/gallery');

  // Delete file from disk (best effort)
  try {
    fs.unlinkSync(path.join(UPLOAD_DIR, item.filename));
  } catch {
    // ignore
  }

  deleteMedia(id);
  res.redirect('/gallery');
});

app.get('/contact', (req, res) => {
  const page = getPage('contact');
  const settings = res.locals.settings;
  res.render('contact', {
    title: 'Contact Us / Find Us',
    pageTitle: page?.title || 'Contact Us / Find Us',
    contentHtml: formatPageContent(page?.content, settings),
    success: req.query.success === '1',
    error: req.query.error || ''
  });
});

app.post('/contact', async (req, res) => {
  const first_name = String(req.body.first_name || '').trim();
  const last_name = String(req.body.last_name || '').trim();
  const phone = String(req.body.phone || '').trim();
  const email = String(req.body.email || '').trim();
  const message = String(req.body.message || '').trim();

  if (!first_name || !last_name || !phone || !email) {
    return res.redirect('/contact?error=' + encodeURIComponent('Please complete all required fields.'));
  }

  if (!validator.isEmail(email)) {
    return res.redirect('/contact?error=' + encodeURIComponent('Please enter a valid email address.'));
  }

  // “Existing email” validation: we do a safe MX lookup to confirm the domain can receive email.
  // This cannot guarantee the mailbox exists (most providers block full verification).
  const hasMx = await emailDomainHasMX(email);
  if (!hasMx) {
    return res.redirect('/contact?error=' + encodeURIComponent('Email domain does not appear to accept email. Please double-check the address.'));
  }

  db.prepare('INSERT INTO contact_messages(first_name,last_name,phone,email,message) VALUES(?,?,?,?,?)')
    .run(first_name, last_name, phone, email, message);

  const forwardTo = getSetting('forward_to_email') || process.env.CONTACT_FORWARD_TO || 'chris@chriswright.info';

  const transport = buildTransport();
  if (!transport) {
    return res.redirect('/contact?error=' + encodeURIComponent('Email sending is not configured. Please call us instead.'));
  }

  const from = process.env.SMTP_FROM || `no-reply@${(process.env.PUBLIC_HOST || 'truckhearse.co.uk')}`;

  await transport.sendMail({
    to: forwardTo,
    from,
    replyTo: email,
    subject: 'Contact From truckhearse.co.uk Website',
    text: `New website contact\n\nName: ${first_name} ${last_name}\nPhone: ${phone}\nEmail: ${email}\n\nMessage:\n${message || '(none)'}`
  });

  res.redirect('/contact?success=1');
});

// ---------- Admin auth ----------
app.get('/login', (req, res) => {
  res.render('login', { title: 'Admin Login', error: req.query.error || '' });
});

app.post('/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const admin = getAdminByEmail(email);
  if (!admin) return res.redirect('/login?error=' + encodeURIComponent('Invalid login'));

  const ok = bcrypt.compareSync(password, admin.password_hash);
  if (!ok) return res.redirect('/login?error=' + encodeURIComponent('Invalid login'));

  req.session.adminId = admin.id;
  res.redirect('/admin');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ---------- First admin setup (only when no admins exist) ----------
app.get('/setup', (req, res) => {
  if (adminCount() > 0) return res.status(404).send('Not found');
  res.render('setup', {
    title: 'Initial Admin Setup',
    error: req.query.error || '',
    setupTokenHint: process.env.SETUP_TOKEN ? 'SETUP_TOKEN is set on the server.' : 'SETUP_TOKEN is not set yet.'
  });
});

app.post('/setup', (req, res) => {
  if (adminCount() > 0) return res.status(404).send('Not found');
  const token = String(req.body.token || '');
  if (!process.env.SETUP_TOKEN || token !== process.env.SETUP_TOKEN) {
    return res.redirect('/setup?error=' + encodeURIComponent('Invalid setup token'));
  }

  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const first_name = String(req.body.first_name || '').trim();
  const last_name = String(req.body.last_name || '').trim();

  if (!validator.isEmail(email) || password.length < 10) {
    return res.redirect('/setup?error=' + encodeURIComponent('Please provide a valid email and a strong password (10+ characters).'));
  }

  const hash = bcrypt.hashSync(password, 12);
  createAdmin({ email, password_hash: hash, first_name, last_name });
  res.redirect('/login');
});

// ---------- Admin dashboard ----------
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin/dashboard', { title: 'Admin Dashboard' });
});

app.get('/admin/pages/:slug', requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const page = getPage(slug);
  if (!page) return res.status(404).send('Not found');
  res.render('admin/edit-page', {
    title: `Edit page: ${slug}`,
    slug,
    page
  });
});

app.post('/admin/pages/:slug', requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const title = String(req.body.title || '').trim().slice(0, 120);
  const content = String(req.body.content || '').trim();
  updatePage(slug, title || slug, content);
  res.redirect('/admin');
});

app.get('/admin/settings', requireAdmin, (req, res) => {
  const settings = listSettings([
    'company_name', 'tagline', 'phone', 'address', 'coverage',
    'forward_to_email', 'map_link', 'what3words_link',
    'facebook_link', 'instagram_link', 'tiktok_link', 'youtube_link'
  ]);
  res.render('admin/settings', { title: 'Site Settings', settings });
});

app.post('/admin/settings', requireAdmin, (req, res) => {
  const keys = [
    'company_name', 'tagline', 'phone', 'address', 'coverage',
    'forward_to_email', 'map_link', 'what3words_link',
    'facebook_link', 'instagram_link', 'tiktok_link', 'youtube_link'
  ];
  for (const k of keys) setSetting(k, String(req.body[k] || '').trim());
  res.redirect('/admin/settings');
});

app.get('/admin/admins', requireAdmin, (req, res) => {
  const admins = listAdmins();
  res.render('admin/admins', { title: 'Manage Admins', admins, error: req.query.error || '' });
});

app.post('/admin/admins/add', requireAdmin, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const first_name = String(req.body.first_name || '').trim();
  const last_name = String(req.body.last_name || '').trim();

  if (!validator.isEmail(email) || password.length < 10) {
    return res.redirect('/admin/admins?error=' + encodeURIComponent('Valid email and 10+ character password required'));
  }

  const hash = bcrypt.hashSync(password, 12);
  try {
    createAdmin({ email, password_hash: hash, first_name, last_name });
  } catch {
    return res.redirect('/admin/admins?error=' + encodeURIComponent('That email is already an admin'));
  }

  res.redirect('/admin/admins');
});

app.post('/admin/admins/:id/reset-password', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const password = String(req.body.password || '');
  if (password.length < 10) return res.redirect('/admin/admins?error=' + encodeURIComponent('Password must be 10+ characters'));

  const hash = bcrypt.hashSync(password, 12);
  updateAdminPassword(id, hash);
  res.redirect('/admin/admins');
});

app.post('/admin/admins/:id/deactivate', requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  const active = db.prepare('SELECT COUNT(*) as c FROM admins WHERE is_active=1').get().c;
  const target = db.prepare('SELECT * FROM admins WHERE id=?').get(id);
  if (!target) return res.redirect('/admin/admins');

  // Prevent removing the last active admin
  if (target.is_active === 1 && active <= 1) {
    return res.redirect('/admin/admins?error=' + encodeURIComponent('You cannot remove the last admin user.'));
  }

  deactivateAdmin(id);

  // If you deactivated yourself, log out
  if (req.admin.id === id) {
    req.session.destroy(() => res.redirect('/'));
    return;
  }

  res.redirect('/admin/admins');
});

// ---------- Health check ----------
app.get('/health', (_req, res) => {
  res.json({ ok: true, db: DB_PATH });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`PNW Carriage Masters site listening on port ${PORT}`);
  console.log("DB ready");
  console.log(`Uploads: ${UPLOAD_DIR}`);
});
