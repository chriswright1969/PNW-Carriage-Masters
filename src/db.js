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

  CREATE TABLE IF NOT EXISTS case_studies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    event_date TEXT,
    vehicle TEXT,
    body_text TEXT NOT NULL DEFAULT '',
    photo_filename TEXT,
    photo_alt TEXT,
    facebook_post_id TEXT UNIQUE,
    facebook_post_url TEXT,
    facebook_image_url TEXT,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    published_at TEXT,
    FOREIGN KEY(created_by) REFERENCES admins(id)
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
setDefault('forward_to_email', 'info@pnwuk.com');
setDefault('map_link', 'https://www.google.com/maps?q=The%20Barn,%20Groesffordd,%20CH8%208LS');
setDefault('what3words_link', 'https://what3words.com/');
setDefault('facebook_link', '');
setDefault('instagram_link', '');
setDefault('tiktok_link', '');
setDefault('youtube_link', '');

ensurePage(
  'home',
  'Welcome',
  `PNW Carriage Masters provides respectful, professional alternative hearse hire across {coverage}.\n\nWe lease bespoke truck / lorry hearses.\n\nWe understand every farewell is unique. 
    Our vehicles are prepared with care, presented immaculately, and operated discreetly in support of your family and funeral director.`
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

export function updateMediaCaption(id, caption) {
  db.prepare('UPDATE media SET caption=? WHERE id=?')
    .run(String(caption || '').trim(), Number(id));
}

export function listCaseStudies() {
  return db.prepare(`
    SELECT *
    FROM case_studies
    ORDER BY
      CASE WHEN status='draft' THEN 0 ELSE 1 END,
      COALESCE(event_date, created_at) DESC,
      id DESC
  `).all();
}

export function listPublishedCaseStudies() {
  return db.prepare(`
    SELECT *
    FROM case_studies
    WHERE status='published'
    ORDER BY COALESCE(event_date, published_at, created_at) DESC, id DESC
  `).all();
}

export function getCaseStudy(id) {
  return db.prepare('SELECT * FROM case_studies WHERE id=?').get(Number(id));
}

export function getCaseStudyByFacebookPostId(postId) {
  return db.prepare('SELECT * FROM case_studies WHERE facebook_post_id=?').get(String(postId || '').trim());
}

export function createCaseStudyDraft({
  slug,
  title,
  event_date,
  vehicle,
  body_text,
  photo_filename,
  photo_alt,
  facebook_post_id,
  facebook_post_url,
  facebook_image_url,
  created_by
}) {
  return db.prepare(`
    INSERT INTO case_studies (
      slug, title, event_date, vehicle, body_text,
      photo_filename, photo_alt,
      facebook_post_id, facebook_post_url, facebook_image_url,
      status, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)
  `).run(
    slug,
    title,
    event_date || null,
    vehicle || '',
    body_text || '',
    photo_filename || '',
    photo_alt || '',
    facebook_post_id || null,
    facebook_post_url || '',
    facebook_image_url || '',
    created_by || null
  );
}

export function updateCaseStudy(id, {
  slug,
  title,
  event_date,
  vehicle,
  body_text,
  photo_filename,
  photo_alt
}) {
  return db.prepare(`
    UPDATE case_studies
    SET slug=?,
        title=?,
        event_date=?,
        vehicle=?,
        body_text=?,
        photo_filename=?,
        photo_alt=?,
        updated_at=datetime('now')
    WHERE id=?
  `).run(
    slug,
    title,
    event_date || null,
    vehicle || '',
    body_text || '',
    photo_filename || '',
    photo_alt || '',
    Number(id)
  );
}

export function publishCaseStudy(id) {
  return db.prepare(`
    UPDATE case_studies
    SET status='published',
        published_at=COALESCE(published_at, datetime('now')),
        updated_at=datetime('now')
    WHERE id=?
  `).run(Number(id));
}

export function moveCaseStudyToDraft(id) {
  return db.prepare(`
    UPDATE case_studies
    SET status='draft',
        updated_at=datetime('now')
    WHERE id=?
  `).run(Number(id));
}

export function deleteCaseStudy(id) {
  return db.prepare('DELETE FROM case_studies WHERE id=?').run(Number(id));
}

export { DATA_DIR, DB_PATH };


