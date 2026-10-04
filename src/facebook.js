import crypto from "crypto";
import fs from "fs";
import path from "path";

const DEFAULT_GRAPH_VERSION = "v26.0";
const MAX_IMAGE_BYTES = 12 * 1024 * 1024;

function getConfig() {
  const pageId = String(process.env.FACEBOOK_PAGE_ID || "").trim();
  const accessToken = String(process.env.FACEBOOK_PAGE_ACCESS_TOKEN || "").trim();
  const version = String(process.env.FACEBOOK_GRAPH_API_VERSION || DEFAULT_GRAPH_VERSION).trim() || DEFAULT_GRAPH_VERSION;

  return {
    pageId,
    accessToken,
    version,
    configured: Boolean(pageId && accessToken)
  };
}

function buildGraphUrl(objectPath, fields, extra = {}) {
  const { version, accessToken } = getConfig();
  const url = new URL(`https://graph.facebook.com/${version}/${objectPath}`);
  url.searchParams.set("access_token", accessToken);
  if (fields) url.searchParams.set("fields", fields);

  for (const [key, value] of Object.entries(extra)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }

  return url;
}

async function graphGet(url) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(15000)
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = payload?.error?.message || `Facebook Graph API returned HTTP ${response.status}`;
    throw new Error(message);
  }

  return payload;
}

export function facebookConfigSummary() {
  const { configured, pageId, version } = getConfig();
  return { configured, pageId, version };
}

export async function fetchFacebookPosts(limit = 20) {
  const cfg = getConfig();

  if (!cfg.configured) {
    throw new Error("Facebook import is not configured. Add FACEBOOK_PAGE_ID and FACEBOOK_PAGE_ACCESS_TOKEN in Render.");
  }

  const safeLimit = Math.max(1, Math.min(50, Number(limit) || 20));
  const fields = "id,message,created_time,permalink_url,full_picture";
  const payload = await graphGet(
    buildGraphUrl(`${cfg.pageId}/posts`, fields, { limit: safeLimit })
  );

  return Array.isArray(payload?.data) ? payload.data : [];
}

export async function fetchFacebookPost(postId) {
  const cfg = getConfig();

  if (!cfg.configured) {
    throw new Error("Facebook import is not configured. Add FACEBOOK_PAGE_ID and FACEBOOK_PAGE_ACCESS_TOKEN in Render.");
  }

  const id = String(postId || "").trim();
  if (!id || !/^[A-Za-z0-9_:-]+$/.test(id)) {
    throw new Error("Invalid Facebook post ID.");
  }

  return graphGet(
    buildGraphUrl(id, "id,message,created_time,permalink_url,full_picture")
  );
}

function isAllowedFacebookImageHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  return (
    host === "facebook.com" ||
    host.endsWith(".facebook.com") ||
    host === "fbcdn.net" ||
    host.endsWith(".fbcdn.net") ||
    host === "fbsbx.com" ||
    host.endsWith(".fbsbx.com")
  );
}

function extensionForMime(mime) {
  const value = String(mime || "").split(";")[0].trim().toLowerCase();
  if (value === "image/png") return ".png";
  if (value === "image/webp") return ".webp";
  if (value === "image/gif") return ".gif";
  return ".jpg";
}

export async function downloadFacebookImage(imageUrl, uploadDir) {
  const raw = String(imageUrl || "").trim();
  if (!raw) return "";

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Facebook returned an invalid image URL.");
  }

  if (url.protocol !== "https:" || !isAllowedFacebookImageHost(url.hostname)) {
    throw new Error("Facebook returned an unexpected image host.");
  }

  const response = await fetch(url, {
    redirect: "follow",
    headers: { Accept: "image/*" },
    signal: AbortSignal.timeout(20000)
  });

  if (!response.ok) {
    throw new Error(`Could not download the Facebook image (HTTP ${response.status}).`);
  }

  let finalUrl;
  try {
    finalUrl = new URL(response.url);
  } catch {
    finalUrl = url;
  }

  if (finalUrl.protocol !== "https:" || !isAllowedFacebookImageHost(finalUrl.hostname)) {
    throw new Error("Facebook image redirected to an unexpected host.");
  }

  const mime = String(response.headers.get("content-type") || "").toLowerCase();
  if (!mime.startsWith("image/")) {
    throw new Error("Facebook did not return an image.");
  }

  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength && declaredLength > MAX_IMAGE_BYTES) {
    throw new Error("Facebook image is larger than 12 MB.");
  }

  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_IMAGE_BYTES) {
    throw new Error("Facebook image is larger than 12 MB.");
  }

  fs.mkdirSync(uploadDir, { recursive: true });

  const filename = `case-facebook-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${extensionForMime(mime)}`;
  fs.writeFileSync(path.join(uploadDir, filename), bytes);

  return filename;
}
