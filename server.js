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

import adminHomeTrucksRoutes from "./src/routes/adminHomeTrucksRoutes.js";
// NOTE: if your actual filename is misspelled (e.g. adminHomeTrcuksRoutes.js),
// either rename the file or change this import to match exactly.

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
app.use(express.static(PUBLIC_DIR));
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

// Compatibility redirects
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

function findAdminByEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  if (!e) return null;

  const a = getAdminByEmail(e);
  if (a) return a;

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
// 3) Ensure branding + home defaults exist (do not overwrite)
// ======================================================
function ensureSetting(key, value) {
  const existing = getSetting(key);
  if (existing === null || existing === undefined || String(existing).trim() === "") {
    setSetting(key, String(value));
  }
}

ensureSetting("logo_file", "");
ensureSetting("logo_version", String(Date.now()));
ensureSetting("logo_home_px", "600");
ensureSetting("logo_home_vw", "90");
ensureSetting("logo_header_h", "44");
ensureSetting("phone", "07503 608944");

// Hero video library
ensureSetting("hero_videos_json", "[]");
ensureSetting("hero_video_current", "");
ensureSetting("hero_video_version", String(Date.now()));

// Home media collections
ensureSetting("home_thumbs_json", "[]");
ensureSetting("home_montage_json", "[]");

// NEW: 2 truck placeholders under video
ensureSetting("home_truck_power_img", "");
ensureSetting("home_truck_power_ver", String(Date.now()));
ensureSetting("home_truck_glory_img", "");
ensureSetting("home_truck_glory_ver", String(Date.now()));

// Settings available everywhere (must be AFTER session so we can read req.session)
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

    // Branding
    "logo_file",
    "logo_version",
    "logo_home_px",
    "logo_home_vw",
    "logo_header_h",

    // Home media (older admin page)
    "home_video_file",
    "home_video_version",
    "home_thumbs_json",
    "home_montage_json",

    // Hero video (current home.ejs uses these)
    "hero_videos_json",
    "hero_video_current",
    "hero_video_version",

    // NEW truck placeholders
    "home_truck_power_img",
    "home_truck_power_ver",
    "home_truck_glory_img",
    "home_truck_glory_ver"
  ]);

  res.locals.settings = settings;
  res.locals.admin = currentAdmin(req);
  next();
});

// NOW mount the admin trucks router (needs session + locals)
app.use("/admin", adminHomeTrucksRoutes);

// ======================================================
// 4) Multer configs
// ======================================================
const logoUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = (path.extname(file.originalname) || "").toLowerCase();
      cb(null, `logo-${Date.now()}${ext}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
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
  limits: { fileSize: 1024 * 1024 * 250 },
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
  limits: { fileSize: 1024 * 1024 * 12 },
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
  limits: { fileSize: 1024 * 1024 * 300 },
  fileFilter: (_req, file, cb) => {
    const ok =
      ["video/mp4", "video/webm", "video/quicktime"].includes(file.mimetype) ||
      file.mimetype.startsWith("video/");
    if (!ok) return cb(new Error("Please upload a video file (MP4/WebM)."));
    cb(null, true);
  }
});

function safeFilename(name) {
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

app.get("/gallery", (_req, res) => {
  const media = listMedia();
  res.render("gallery", { title: "Gallery", media });
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
  limits: { fileSize: 1024 * 1024 * 200 },
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
  } catch {}

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
    return res.redirect("/contact?error=" + encodeURIComponent("Email domain does not appear to accept email."));
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
    return res.redirect("/contact?error=" + encodeURIComponent("Email sending is not configured. Please call us instead."));
  }

  const from = process.env.SMTP_FROM || `no-reply@${process.env.PUBLIC_HOST || "truckhearse.co.uk"}`;

  await transport.sendMail({
    to: forwardTo,
    from,
    replyTo: email,
    subject: "Contact From truckhearse.co.uk Website",
    text:
      `New website contact\n\nName: ${first_name} ${last_name}\nPhone: ${phone}\nEmail: ${email}\n\nMessage:\n` +
      (message || "(none)")
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
    return res.redirect("/setup?error=" + encodeURIComponent("Valid email + strong password (10+ chars) required."));
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
  res.render("admin/edit-page", { title: `Edit page: ${slug}`, slug, page });
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
// Branding routes (logo upload + size settings)
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

    setSetting("logo_home_px", clampInt(req.body.logo_home_px, 120, 1200, 600));
    setSetting("logo_home_vw", clampInt(req.body.logo_home_vw, 20, 100, 90));
    setSetting("logo_header_h", clampInt(req.body.logo_header_h, 20, 120, 44));

    if (req.file?.filename) {
      setSetting("logo_file", req.file.filename);
      setSetting("logo_version", String(Date.now()));
    }

    res.redirect("/admin/branding?ok=1");
  });
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
