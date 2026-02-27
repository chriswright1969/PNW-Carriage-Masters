// server.js
import "dotenv/config";

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
} from "./src/db.js";

const app = express();
const PORT = process.env.PORT || 3000;

const ROOT_DIR = process.cwd();
const PUBLIC_DIR = path.join(ROOT_DIR, "public");

// ======================================================
// 1) Persistent uploads directory + public mount (/uploads)
// ======================================================
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// --------------------
// View engine
// --------------------
app.set("view engine", "ejs");
app.set("views", path.join(ROOT_DIR, "views"));

// --------------------
// Middleware
// --------------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("combined"));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.json({ limit: "2mb" }));

// Render sits behind a reverse proxy (needed for secure cookies)
app.set("trust proxy", 1);

// --------------------
// Static assets
// --------------------
// Serve /public at the site root so these work:
//   /css/site.css  -> public/css/site.css
//   /images/logo.png -> public/images/logo.png
app.use(express.static(PUBLIC_DIR));

// Also keep explicit mounts (fine either way; these help clarity)
app.use("/css", express.static(path.join(PUBLIC_DIR, "css")));
app.use("/js", express.static(path.join(PUBLIC_DIR, "js")));
app.use("/images", express.static(path.join(PUBLIC_DIR, "images")));

// Uploaded media persisted on disk
app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    maxAge: "7d",
    setHeaders(res) {
      res.setHeader("X-Content-Type-Options", "nosniff");
    }
  })
);

// Compatibility redirects for common old/typo paths
app.get("/css.site.css", (_req, res) => res.redirect(301, "/css/site.css"));
app.get("/site.css", (_req, res) => res.redirect(301, "/css/site.css"));

// --------------------
// Sessions (ONE time only)
// --------------------
const SqliteStore = createSqliteStore(session);
const sessionStore = new SqliteStore({
  client: db,
  expired: 1000 * 60 * 60 * 24 * 14, // 14 days
  clearInterval: 1000 * 60 * 60 // cleanup hourly
});

app.use(
  session({
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
  })
);

// --------------------
// Helpers
// --------------------
function currentAdmin(req) {
  const id = req.session?.adminId;
  if (!id) return null;
  return getAdminById(id);
}

function requireAdmin(req, res, next) {
  const admin = currentAdmin(req);
  if (!admin) return res.redirect("/login");
  req.admin = admin;
  next();
}

function formatPageContent(raw, settings) {
  const tokens = {
    "{coverage}": settings.coverage,
    "{phone}": settings.phone,
    "{company_name}": settings.company_name,
    "{tagline}": settings.tagline
  };

  let text = String(raw || "");
  for (const [k, v] of Object.entries(tokens)) {
    text = text.split(k).join(String(v || ""));
  }

  const cleaned = sanitizeHtml(text, {
    allowedTags: ["b", "strong", "i", "em", "u", "br", "p", "ul", "ol", "li", "a"],
    allowedAttributes: { a: ["href", "target", "rel"] },
    transformTags: {
      a: sanitizeHtml.simpleTransform("a", { rel: "noopener noreferrer", target: "_blank" }, true)
    }
  });

  // If there are no <p> tags, turn blank-line separated text into paragraphs
  if (!cleaned.includes("<p")) {
    const parts = cleaned
      .split(/\n\n+/)
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`)
      .join("\n");
    return parts || "";
  }

  return cleaned;
}

async function emailDomainHasMX(email) {
  const domain = String(email).split("@")[1];
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

// Robust admin lookup (avoids “Invalid login” due to email case/space mismatch)
function findAdminByEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  if (!e) return null;

  // 1) Use your helper (if it already normalizes, great)
  const a = getAdminByEmail(e);
  if (a) return a;

  // 2) Fallback to case/trim-insensitive lookup
  return db
    .prepare(
      `SELECT * FROM admins
       WHERE is_active=1
         AND lower(trim(email)) = lower(trim(?))
       LIMIT 1`
    )
    .get(e);
}

// ======================================================
// 3) Ensure branding defaults exist (do not overwrite)
// ======================================================
function ensureSetting(key, value) {
  const existing = getSetting(key);
  if (existing === null || existing === undefined || String(existing).trim() === "") {
    setSetting(key, String(value));
  }
}

ensureSetting("logo_file", ""); // empty means "use fallback in /public"
ensureSetting("logo_version", String(Date.now())); // cache-bust query string
ensureSetting("logo_home_px", "600");
ensureSetting("logo_home_vw", "90");
ensureSetting("logo_header_h", "44");
ensureSetting("phone", "07503 608944");

// Hero video library
ensureSetting("hero_videos_json", "[]");                 // [{ filename, original, uploadedAt }]
ensureSetting("hero_video_current", "");                 // filename of selected clip
ensureSetting("hero_video_version", String(Date.now())); // cache-bust
ensureSetting("home_thumbs_json", "[]");   // array of image filenames
ensureSetting("home_montage_json", "[]");  // array of image filenames

// Settings available everywhere
app.use((req, res, next) => {
  const settings = listSettings([
    "company_name",
    "tagline",
    "phone",
    "coverage",
    "facebook_link",
    "instagram_link",
    "tiktok_link",
    "youtube_link",

    // Branding settings
    "logo_file",
    "logo_version",
    "logo_home_px",
    "logo_home_vw",
    "logo_header_h",
    "home_video_file",
    "home_video_version",
    "home_thumbs_json",
    "home_montage_json",
     // NEW hero video keys (next section)
    "hero_videos_json",
    "hero_video_current",
    "hero_video_version"
  ]);
  res.locals.settings = settings;
  res.locals.admin = currentAdmin(req);
  next();
});

// ======================================================
// 2) Multer config for logo uploads (PNG/JPG/WebP, 2MB)
// ======================================================
const logoUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = (path.extname(file.originalname) || "").toLowerCase();
      cb(null, `logo-${Date.now()}${ext}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (_req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp"].includes(file.mimetype);
    if (!ok) return cb(new Error("Only PNG, JPG, or WebP files are allowed"));
    cb(null, true);
  }
});

const homeVideoUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = (path.extname(file.originalname) || "").toLowerCase();
      cb(null, `home-video-${Date.now()}${ext}`);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 250 }, // 250MB
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype.startsWith("video/");
    if (!ok) return cb(new Error("Hero clip must be a video file (mp4/webm)."));
    cb(null, true);
  }
});

const homeImageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = (path.extname(file.originalname) || "").toLowerCase();
      cb(null, `home-img-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 12 }, // 12MB per image
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype.startsWith("image/");
    if (!ok) return cb(new Error("Only image files are allowed."));
    cb(null, true);
  }
});

const heroVideoUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = (path.extname(file.originalname) || "").toLowerCase();
      cb(null, `hero-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 300 }, // 300MB
  fileFilter: (_req, file, cb) => {
    const ok = ["video/mp4", "video/webm", "video/quicktime"].includes(file.mimetype) || file.mimetype.startsWith("video/");
    if (!ok) return cb(new Error("Please upload a video file (MP4/WebM)."));
    cb(null, true);
  }
});

function safeFilename(name) {
  // prevent path traversal
  const s = String(name || "");
  return /^[a-zA-Z0-9._-]+$/.test(s) ? s : "";
}

function parseJsonArray(s) {
  try {
    const v = JSON.parse(String(s || "[]"));
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function writeJsonArraySetting(key, arr) {
  setSetting(key, JSON.stringify(Array.isArray(arr) ? arr : []));
}

// --------------------
// Routes
// --------------------
app.get("/", (req, res) => {
  const page = getPage("home");
  const settings = res.locals.settings;

  const thumbs = parseJsonArray(settings.home_thumbs_json);
  const montage = parseJsonArray(settings.home_montage_json);

  res.render("home", {
    title: `${settings.company_name} – ${settings.tagline}`,
    pageTitle: page?.title || "Welcome",
    contentHtml: formatPageContent(page?.content, settings),
    thumbs,
    montage
  });
});

app.get("/gallery", (req, res) => {
  const media = listMedia();
  res.render("gallery", {
    title: "Gallery",
    media
  });
});

// Uploads (admin only) - gallery media
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const name = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`;
      cb(null, name);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 200 }, // 200MB
  fileFilter: (_req, file, cb) => {
    const okImage = file.mimetype.startsWith("image/");
    const okVideo = file.mimetype.startsWith("video/");
    if (!okImage && !okVideo) return cb(new Error("Only images or video files are allowed"));
    cb(null, true);
  }
});

app.post("/admin/upload", requireAdmin, upload.single("media"), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send("No file uploaded");

  const type = file.mimetype.startsWith("video/") ? "video" : "image";
  const caption = String(req.body.caption || "").slice(0, 200);

  addMedia({
    type,
    filename: file.filename,
    original_name: file.originalname,
    caption,
    mime: file.mimetype,
    uploaded_by: req.admin.id
  });

  res.redirect("/gallery");
});

app.post("/admin/media/:id/delete", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const item = getMedia(id);
  if (!item) return res.redirect("/gallery");

  try {
    fs.unlinkSync(path.join(UPLOAD_DIR, item.filename));
  } catch {
    // ignore
  }

  deleteMedia(id);
  res.redirect("/gallery");
});

app.get("/contact", (req, res) => {
  const page = getPage("contact");
  const settings = res.locals.settings;
  res.render("contact", {
    title: "Contact Us / Find Us",
    pageTitle: page?.title || "Contact Us / Find Us",
    contentHtml: formatPageContent(page?.content, settings),
    success: req.query.success === "1",
    error: req.query.error || ""
  });
});

app.post("/contact", async (req, res) => {
  const first_name = String(req.body.first_name || "").trim();
  const last_name = String(req.body.last_name || "").trim();
  const phone = String(req.body.phone || "").trim();
  const email = String(req.body.email || "").trim();
  const message = String(req.body.message || "").trim();

  if (!first_name || !last_name || !phone || !email) {
    return res.redirect("/contact?error=" + encodeURIComponent("Please complete all required fields."));
  }

  if (!validator.isEmail(email)) {
    return res.redirect("/contact?error=" + encodeURIComponent("Please enter a valid email address."));
  }

  const hasMx = await emailDomainHasMX(email);
  if (!hasMx) {
    return res.redirect(
      "/contact?error=" +
        encodeURIComponent("Email domain does not appear to accept email. Please double-check the address.")
    );
  }

  db.prepare("INSERT INTO contact_messages(first_name,last_name,phone,email,message) VALUES(?,?,?,?,?)").run(
    first_name,
    last_name,
    phone,
    email,
    message
  );

  const forwardTo = getSetting("forward_to_email") || process.env.CONTACT_FORWARD_TO || "chris@chriswright.info";
  const transport = buildTransport();
  if (!transport) {
    return res.redirect(
      "/contact?error=" + encodeURIComponent("Email sending is not configured. Please call us instead.")
    );
  }

  const from = process.env.SMTP_FROM || `no-reply@${process.env.PUBLIC_HOST || "truckhearse.co.uk"}`;

  await transport.sendMail({
    to: forwardTo,
    from,
    replyTo: email,
    subject: "Contact From truckhearse.co.uk Website",
    text: `New website contact\n\nName: ${first_name} ${last_name}\nPhone: ${phone}\nEmail: ${email}\n\nMessage:\n${
      message || "(none)"
    }`
  });

  res.redirect("/contact?success=1");
});

// --------------------
// Admin auth
// --------------------
app.get("/login", (req, res) => {
  res.render("login", { title: "Admin Login", error: req.query.error || "" });
});

app.post("/login", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const admin = findAdminByEmail(email);
  if (!admin) return res.redirect("/login?error=" + encodeURIComponent("Invalid login"));

  const ok = bcrypt.compareSync(password, admin.password_hash);
  if (!ok) return res.redirect("/login?error=" + encodeURIComponent("Invalid login"));

  req.session.adminId = admin.id;

  // ensure session is saved before redirect (helps on some hosts)
  req.session.save(() => res.redirect("/admin"));
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// --------------------
// First admin setup (only when no admins exist)
// --------------------
app.get("/setup", (req, res) => {
  if (adminCount() > 0) return res.status(404).send("Not found");
  res.render("setup", {
    title: "Initial Admin Setup",
    error: req.query.error || "",
    setupTokenHint: process.env.SETUP_TOKEN ? "SETUP_TOKEN is set on the server." : "SETUP_TOKEN is not set yet."
  });
});

app.post("/setup", (req, res) => {
  if (adminCount() > 0) return res.status(404).send("Not found");

  const token = String(req.body.token || "");
  if (!process.env.SETUP_TOKEN || token !== process.env.SETUP_TOKEN) {
    return res.redirect("/setup?error=" + encodeURIComponent("Invalid setup token"));
  }

  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const first_name = String(req.body.first_name || "").trim();
  const last_name = String(req.body.last_name || "").trim();

  if (!validator.isEmail(email) || password.length < 10) {
    return res.redirect(
      "/setup?error=" + encodeURIComponent("Please provide a valid email and a strong password (10+ characters).")
    );
  }

  const hash = bcrypt.hashSync(password, 12);
  createAdmin({ email, password_hash: hash, first_name, last_name });
  res.redirect("/login");
});

// --------------------
// Admin dashboard + CMS
// --------------------
app.get("/admin", requireAdmin, (_req, res) => {
  res.render("admin/dashboard", { title: "Admin Dashboard" });
});

app.get("/admin/pages/:slug", requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const page = getPage(slug);
  if (!page) return res.status(404).send("Not found");
  res.render("admin/edit-page", {
    title: `Edit page: ${slug}`,
    slug,
    page
  });
});

app.post("/admin/pages/:slug", requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const title = String(req.body.title || "").trim().slice(0, 120);
  const content = String(req.body.content || "").trim();
  updatePage(slug, title || slug, content);
  res.redirect("/admin");
});

app.get("/admin/settings", requireAdmin, (_req, res) => {
  const settings = listSettings([
    "company_name",
    "tagline",
    "phone",
    "coverage",
    "forward_to_email",
    "facebook_link",
    "instagram_link",
    "tiktok_link",
    "youtube_link"
  ]);
  res.render("admin/settings", { title: "Site Settings", settings });
});

app.post("/admin/settings", requireAdmin, (req, res) => {
  const keys = [
    "company_name",
    "tagline",
    "phone",
    "coverage",
    "forward_to_email",
    "facebook_link",
    "instagram_link",
    "tiktok_link",
    "youtube_link"
  ];
  for (const k of keys) setSetting(k, String(req.body[k] || "").trim());
  res.redirect("/admin/settings");
});

// ======================================================
// 4) Admin branding routes (logo upload + size settings)
// ======================================================
app.get("/admin/branding", requireAdmin, (req, res) => {
  res.render("admin/branding", {
    title: "Branding",
    message: req.query.ok === "1" ? "Saved." : null,
    errorMsg: null,
    logo_file: getSetting("logo_file") || "",
    logo_home_px: getSetting("logo_home_px") || "600",
    logo_home_vw: getSetting("logo_home_vw") || "90",
    logo_header_h: getSetting("logo_header_h") || "44"
  });
});

app.post("/admin/branding", requireAdmin, (req, res) => {
  // capture multer errors so the user sees a nice message
  logoUpload.single("logo")(req, res, (err) => {
    if (err) {
      return res.status(400).render("admin/branding", {
        title: "Branding",
        message: null,
        errorMsg: err.message || "Upload failed",
        logo_file: getSetting("logo_file") || "",
        logo_home_px: getSetting("logo_home_px") || "600",
        logo_home_vw: getSetting("logo_home_vw") || "90",
        logo_header_h: getSetting("logo_header_h") || "44"
      });
    }

    const clampInt = (v, min, max, fallback) => {
      const n = Number.parseInt(String(v ?? ""), 10);
      if (!Number.isFinite(n)) return String(fallback);
      return String(Math.max(min, Math.min(max, n)));
    };

    // sizes (save even if no file uploaded)
    setSetting("logo_home_px", clampInt(req.body.logo_home_px, 120, 1200, 600));
    setSetting("logo_home_vw", clampInt(req.body.logo_home_vw, 20, 100, 90));
    setSetting("logo_header_h", clampInt(req.body.logo_header_h, 20, 120, 44));

    // if a new logo was uploaded, store filename + bump version to bust caches
    if (req.file?.filename) {
      setSetting("logo_file", req.file.filename);
      setSetting("logo_version", String(Date.now()));
    }

    res.redirect("/admin/branding?ok=1");
  });
});

app.get("/admin/admins", requireAdmin, (req, res) => {
  const admins = listAdmins();
  res.render("admin/admins", { title: "Manage Admins", admins, error: req.query.error || "" });
});

app.post("/admin/admins/add", requireAdmin, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const first_name = String(req.body.first_name || "").trim();
  const last_name = String(req.body.last_name || "").trim();

  if (!validator.isEmail(email) || password.length < 10) {
    return res.redirect("/admin/admins?error=" + encodeURIComponent("Valid email and 10+ character password required"));
  }

  const hash = bcrypt.hashSync(password, 12);
  try {
    createAdmin({ email, password_hash: hash, first_name, last_name });
  } catch {
    return res.redirect("/admin/admins?error=" + encodeURIComponent("That email is already an admin"));
  }

  res.redirect("/admin/admins");
});

app.post("/admin/admins/:id/reset-password", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const password = String(req.body.password || "");
  if (password.length < 10) {
    return res.redirect("/admin/admins?error=" + encodeURIComponent("Password must be 10+ characters"));
  }

  const hash = bcrypt.hashSync(password, 12);
  updateAdminPassword(id, hash);
  res.redirect("/admin/admins");
});

app.post("/admin/admins/:id/deactivate", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  const active = db.prepare("SELECT COUNT(*) as c FROM admins WHERE is_active=1").get().c;
  const target = db.prepare("SELECT * FROM admins WHERE id=?").get(id);
  if (!target) return res.redirect("/admin/admins");

  if (target.is_active === 1 && active <= 1) {
    return res.redirect("/admin/admins?error=" + encodeURIComponent("You cannot remove the last admin user."));
  }

  deactivateAdmin(id);

  if (req.admin.id === id) {
    req.session.destroy(() => res.redirect("/"));
    return;
  }

  res.redirect("/admin/admins");
});

app.get("/admin/home-media", requireAdmin, (_req, res) => {
  const settings = res.locals.settings;
  res.render("admin/home-media", {
    title: "Home Media",
    message: _req.query.ok === "1" ? "Saved." : null,
    errorMsg: _req.query.error || "",
    videoFile: settings.home_video_file || "",
    videoVer: settings.home_video_version || "",
    thumbs: parseJsonArray(settings.home_thumbs_json),
    montage: parseJsonArray(settings.home_montage_json)
  });
});

app.post("/admin/home-media/video", requireAdmin, (req, res) => {
  homeVideoUpload.single("heroVideo")(req, res, (err) => {
    if (err) return res.redirect("/admin/home-media?error=" + encodeURIComponent(err.message));

    if (!req.file?.filename) {
      return res.redirect("/admin/home-media?error=" + encodeURIComponent("No video uploaded."));
    }

    setSetting("home_video_file", req.file.filename);
    setSetting("home_video_version", String(Date.now())); // cache-bust

    return res.redirect("/admin/home-media?ok=1");
  });
});

app.post("/admin/home-media/video/clear", requireAdmin, (_req, res) => {
  // Optional: delete old file too
  const old = getSetting("home_video_file") || "";
  if (old) {
    try { fs.unlinkSync(path.join(UPLOAD_DIR, old)); } catch {}
  }
  setSetting("home_video_file", "");
  setSetting("home_video_version", String(Date.now()));
  res.redirect("/admin/home-media?ok=1");
});

app.post("/admin/home-media/thumbs/add", requireAdmin, (req, res) => {
  homeImageUpload.array("thumbs", 24)(req, res, (err) => {
    if (err) return res.redirect("/admin/home-media?error=" + encodeURIComponent(err.message));
    const files = (req.files || []).map(f => f.filename).filter(Boolean);
    if (!files.length) return res.redirect("/admin/home-media?error=" + encodeURIComponent("No images uploaded."));

    const current = parseJsonArray(getSetting("home_thumbs_json"));
    const next = current.concat(files).slice(0, 60); // cap
    setSetting("home_thumbs_json", JSON.stringify(next));

    res.redirect("/admin/home-media?ok=1");
  });
});

app.post("/admin/home-media/montage/add", requireAdmin, (req, res) => {
  homeImageUpload.array("montage", 60)(req, res, (err) => {
    if (err) return res.redirect("/admin/home-media?error=" + encodeURIComponent(err.message));
    const files = (req.files || []).map(f => f.filename).filter(Boolean);
    if (!files.length) return res.redirect("/admin/home-media?error=" + encodeURIComponent("No images uploaded."));

    const current = parseJsonArray(getSetting("home_montage_json"));
    const next = current.concat(files).slice(0, 200); // cap
    setSetting("home_montage_json", JSON.stringify(next));

    res.redirect("/admin/home-media?ok=1");
  });
});

app.post("/admin/home-media/thumbs/:name/delete", requireAdmin, (req, res) => {
  const name = safeFilename(req.params.name);
  if (!name) return res.redirect("/admin/home-media?error=" + encodeURIComponent("Invalid filename."));

  const current = parseJsonArray(getSetting("home_thumbs_json"));
  const next = current.filter(x => x !== name);
  setSetting("home_thumbs_json", JSON.stringify(next));

  try { fs.unlinkSync(path.join(UPLOAD_DIR, name)); } catch {}
  res.redirect("/admin/home-media?ok=1");
});

app.post("/admin/home-media/montage/:name/delete", requireAdmin, (req, res) => {
  const name = safeFilename(req.params.name);
  if (!name) return res.redirect("/admin/home-media?error=" + encodeURIComponent("Invalid filename."));

  const current = parseJsonArray(getSetting("home_montage_json"));
  const next = current.filter(x => x !== name);
  setSetting("home_montage_json", JSON.stringify(next));

  try { fs.unlinkSync(path.join(UPLOAD_DIR, name)); } catch {}
  res.redirect("/admin/home-media?ok=1");
});

app.get("/admin/hero-video", requireAdmin, (req, res) => {
  const settings = res.locals.settings;
  const videos = parseJsonArray(settings.hero_videos_json);
  res.render("admin/hero-video", {
    title: "Hero Video",
    message: req.query.ok === "1" ? "Saved." : null,
    errorMsg: req.query.error || "",
    videos,
    current: settings.hero_video_current || "",
    version: settings.hero_video_version || ""
  });
});

app.post("/admin/hero-video/upload", requireAdmin, (req, res) => {
  heroVideoUpload.single("heroVideo")(req, res, (err) => {
    if (err) return res.redirect("/admin/hero-video?error=" + encodeURIComponent(err.message));
    if (!req.file?.filename) return res.redirect("/admin/hero-video?error=" + encodeURIComponent("No video uploaded."));

    const currentList = parseJsonArray(getSetting("hero_videos_json"));
    const item = {
      filename: req.file.filename,
      original: req.file.originalname,
      uploadedAt: Date.now()
    };
    currentList.unshift(item); // newest first
    writeJsonArraySetting("hero_videos_json", currentList);

    // auto-select the newly uploaded one
    setSetting("hero_video_current", req.file.filename);
    setSetting("hero_video_version", String(Date.now()));

    res.redirect("/admin/hero-video?ok=1");
  });
});

app.post("/admin/hero-video/select", requireAdmin, (req, res) => {
  const filename = safeFilename(req.body.filename);
  if (!filename) return res.redirect("/admin/hero-video?error=" + encodeURIComponent("Invalid selection."));

  const list = parseJsonArray(getSetting("hero_videos_json"));
  const exists = list.some(v => v && v.filename === filename);
  if (!exists) return res.redirect("/admin/hero-video?error=" + encodeURIComponent("That video no longer exists."));

  setSetting("hero_video_current", filename);
  setSetting("hero_video_version", String(Date.now()));
  res.redirect("/admin/hero-video?ok=1");
});

app.post("/admin/hero-video/clear", requireAdmin, (_req, res) => {
  setSetting("hero_video_current", "");
  setSetting("hero_video_version", String(Date.now()));
  res.redirect("/admin/hero-video?ok=1");
});

app.post("/admin/hero-video/:filename/delete", requireAdmin, (req, res) => {
  const filename = safeFilename(req.params.filename);
  if (!filename) return res.redirect("/admin/hero-video?error=" + encodeURIComponent("Invalid filename."));

  const list = parseJsonArray(getSetting("hero_videos_json")).filter(v => v && v.filename !== filename);
  writeJsonArraySetting("hero_videos_json", list);

  try { fs.unlinkSync(path.join(UPLOAD_DIR, filename)); } catch {}

  const current = String(getSetting("hero_video_current") || "");
  if (current === filename) {
    // if current deleted, pick next available or clear
    const next = list[0]?.filename || "";
    setSetting("hero_video_current", next);
  }
  setSetting("hero_video_version", String(Date.now()));

  res.redirect("/admin/hero-video?ok=1");
});

// --------------------
// Health check
// --------------------
app.get("/health", (_req, res) => {
  res.json({ ok: true, db: DB_PATH });
});

// --------------------
// Errors
// --------------------
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).send("Server error");
});

// --------------------
// Start
// --------------------
app.listen(PORT, () => {
  console.log(`PNW Carriage Masters site listening on port ${PORT}`);
  console.log(`DB: ${DB_PATH}`);
  console.log(`Uploads: ${UPLOAD_DIR}`);
});
