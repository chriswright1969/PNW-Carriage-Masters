# PNW Carriage Masters (truckhearse.co.uk)

Sombre, respectful website for an **Alternative Hearse Hire** company.

**Stack:** Node.js + Express + EJS + SQLite (`better-sqlite3`) + Multer uploads + Nodemailer.

## Features

- Landing page (editable by admins)
- Photo / video gallery
  - Public can view thumbnails and open a lightbox viewer (prev/next/close)
  - Admins can upload new images/videos and delete existing items
- Contact / Find us page
  - Validates email format and checks the email domain has MX records (does not guarantee mailbox exists)
  - Forwards messages via SMTP to a configurable recipient (admin-editable)
- Admin system
  - Login/logout, manage pages, settings, media, and admin accounts
  - Prevents deletion/deactivation of the **last active admin**
- Render Persistent Disk support
  - DB + uploads stored under the disk mount path so they persist across deploys/restarts

## Local run

```bash
npm install
cp .env.example .env
npm run dev
```

Then open: http://localhost:3000

## First admin creation (reliable)

### Option A (recommended): CLI

```bash
npm run create-admin -- admin@example.com 'StrongPassword123' Chris Wright
```

### Option B: guarded /setup page (Render)

1. Set env var `SETUP_TOKEN` on the server.
2. Visit: `/setup?token=YOUR_SETUP_TOKEN`
3. Create the first admin.

The setup route is only available when **no admin users exist**.

## Persistent storage layout

- `DATA_DIR=/var/data` (Render disk mount path)
- DB default: `/var/data/pnw.sqlite`
- Uploads default: `/var/data/uploads`

## SMTP

The contact form uses Nodemailer. Configure these env vars:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM` (e.g. `truckhearse.co.uk <no-reply@truckhearse.co.uk>`)

If these are not set, contact form submission will return an error.

---

## Notes

- Videos: keep them short (web-friendly) and consider MP4/H.264 for best compatibility.
- Upload limits: 25 MB per file by default (change in `server.js`).
