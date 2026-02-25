import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'pnw.sqlite');

// Ensure data directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS pages (
    slug TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK (type IN ('image','video')),
    filename TEXT NOT NULL,
    original_name TEXT,
    caption TEXT,
    mime TEXT,
    uploaded_by INTEGER,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(uploaded_by) REFERENCES admins(id)
  );

  CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

function setDefault(key, value) {
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get(key);
  if (!row) db.prepare('INSERT INTO settings(key,value) VALUES(?,?)').run(key, value);
}

function ensurePage(slug, title, content) {
  const row = db.prepare('SELECT slug FROM pages WHERE slug=?').get(slug);
  if (!row) {
    db.prepare('INSERT INTO pages(slug,title,content) VALUES(?,?,?)').run(slug, title, content);
  }
}

// Defaults (admin can change in dashboard)
setDefault('company_name', 'PNW Carriage Masters');
setDefault('tagline', 'Alternative Hearse Hire');
setDefault('phone', '07503 608944');
setDefault('address', 'The Barn, Groesffordd, CH8 8LS');
setDefault('coverage', 'North Wales, Chester, Wrexham, Shrewsbury, Liverpool, Wirral and Warrington');
setDefault('forward_to_email', 'chris@chriswright.info');
setDefault('map_link', 'https://www.google.com/maps?q=The%20Barn,%20Groesffordd,%20CH8%208LS');
setDefault('what3words_link', 'https://what3words.com/');
setDefault('facebook_link', '');
setDefault('instagram_link', '');
setDefault('tiktok_link', '');
setDefault('youtube_link', '');

ensurePage(
  'home',
  'Welcome',
  `PNW Carriage Masters provides respectful, professional alternative hearse hire across {coverage}.\n\nWe lease a bespoke truck hearse, a classic black Rolls‑Royce hearse and limousine, and a classic white Daimler hearse and limousine.\n\nWe understand every farewell is unique. Our vehicles are prepared with care, presented immaculately, and operated discreetly in support of your family and funeral director.`
);

ensurePage(
  'contact',
  'Contact Us / Find Us',
  `For enquiries, availability and pricing, please use the contact form below or call us.\n\nWe are based at {address} and cover {coverage}.`
);

export function getSetting(key) {
  return db.prepare('SELECT value FROM settings WHERE key=?').get(key)?.value;
}

export function setSetting(key, value) {
  db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, String(value ?? ''));
}

export function listSettings(keys) {
  const stmt = db.prepare('SELECT key, value FROM settings WHERE key IN (' + keys.map(() => '?').join(',') + ')');
  const rows = stmt.all(...keys);
  const out = {};
  for (const k of keys) out[k] = '';
  for (const r of rows) out[r.key] = r.value;
  return out;
}

export function getPage(slug) {
  return db.prepare('SELECT * FROM pages WHERE slug=?').get(slug);
}

export function updatePage(slug, title, content) {
  db.prepare('UPDATE pages SET title=?, content=?, updated_at=datetime(\'now\') WHERE slug=?').run(title, content, slug);
}

export function adminCount() {
  return db.prepare('SELECT COUNT(*) as c FROM admins WHERE is_active=1').get().c;
}

export function getAdminByEmail(email) {
  return db.prepare('SELECT * FROM admins WHERE email=? AND is_active=1').get(email);
}

export function getAdminById(id) {
  return db.prepare('SELECT * FROM admins WHERE id=? AND is_active=1').get(id);
}

export function listAdmins() {
  return db.prepare('SELECT id, email, first_name, last_name, is_active, created_at FROM admins ORDER BY created_at ASC').all();
}

export function createAdmin({ email, password_hash, first_name, last_name }) {
  return db.prepare('INSERT INTO admins(email,password_hash,first_name,last_name,is_active) VALUES(?,?,?,?,1)').run(email, password_hash, first_name || '', last_name || '');
}

export function deactivateAdmin(id) {
  db.prepare('UPDATE admins SET is_active=0 WHERE id=?').run(id);
}

export function updateAdminPassword(id, password_hash) {
  db.prepare('UPDATE admins SET password_hash=? WHERE id=?').run(password_hash, id);
}

export function addMedia({ type, filename, original_name, caption, mime, uploaded_by }) {
  db.prepare('INSERT INTO media(type,filename,original_name,caption,mime,uploaded_by) VALUES(?,?,?,?,?,?)')
    .run(type, filename, original_name || '', caption || '', mime || '', uploaded_by || null);
}

export function listMedia() {
  return db.prepare('SELECT * FROM media ORDER BY uploaded_at DESC, id DESC').all();
}

export function getMedia(id) {
  return db.prepare('SELECT * FROM media WHERE id=?').get(id);
}

export function deleteMedia(id) {
  db.prepare('DELETE FROM media WHERE id=?').run(id);
}

export { DATA_DIR, DB_PATH };
