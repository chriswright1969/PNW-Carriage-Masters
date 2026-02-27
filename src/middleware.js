// /src/middleware.js
import { getAdminById } from "./db.js";

export function currentAdmin(req) {
  const id = req.session?.adminId;
  if (!id) return null;
  return getAdminById(id);
}

export function requireAdmin(req, res, next) {
  const admin = currentAdmin(req);
  if (!admin) return res.redirect("/login");
  req.admin = admin;
  next();
}
