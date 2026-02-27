// /src/routes/adminHomeTrucksRoutes.js
import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";

import { requireAdmin } from "../middleware.js";
import { getSetting, setSetting } from "../db.js";

const router = express.Router();

const uploadDir = "/var/data/uploads"; // your persistent disk folder (matches /uploads usage)
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(ext) ? ext : ".jpg";
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${safeExt}`);
  },
});

const allowed = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB
  fileFilter: (req, file, cb) => {
    if (!allowed.has(file.mimetype)) return cb(new Error("Only JPG/PNG/WEBP/GIF allowed"));
    cb(null, true);
  },
});

function nowVer() {
  return String(Date.now());
}

router.get("/home-trucks", requireAdmin, (req, res) => {
  const powerImg = getSetting("home_truck_power_img") || "";
  const gloryImg = getSetting("home_truck_glory_img") || "";
  const powerVer = getSetting("home_truck_power_ver") || "";
  const gloryVer = getSetting("home_truck_glory_ver") || "";

  res.render("admin/home-trucks", {
    title: "Home trucks",
    powerImg, gloryImg, powerVer, gloryVer,
    message: null,
    errorMsg: null,
  });
});

router.post(
  "/home-trucks",
  requireAdmin,
  upload.fields([
    { name: "power_img", maxCount: 1 },
    { name: "glory_img", maxCount: 1 },
  ]),
  (req, res) => {
    try {
      let powerImg = getSetting("home_truck_power_img") || "";
      let gloryImg = getSetting("home_truck_glory_img") || "";
      let powerVer = getSetting("home_truck_power_ver") || "";
      let gloryVer = getSetting("home_truck_glory_ver") || "";

      if (req.body?.clear_power === "1") {
        setSetting("home_truck_power_img", "");
        setSetting("home_truck_power_ver", nowVer());
        powerImg = "";
        powerVer = getSetting("home_truck_power_ver") || "";
      }
      if (req.body?.clear_glory === "1") {
        setSetting("home_truck_glory_img", "");
        setSetting("home_truck_glory_ver", nowVer());
        gloryImg = "";
        gloryVer = getSetting("home_truck_glory_ver") || "";
      }

      if (req.files?.power_img?.[0]) {
        powerImg = req.files.power_img[0].filename;
        powerVer = nowVer();
        setSetting("home_truck_power_img", powerImg);
        setSetting("home_truck_power_ver", powerVer);
      }
      if (req.files?.glory_img?.[0]) {
        gloryImg = req.files.glory_img[0].filename;
        gloryVer = nowVer();
        setSetting("home_truck_glory_img", gloryImg);
        setSetting("home_truck_glory_ver", gloryVer);
      }

      res.render("admin/home-trucks", {
        title: "Home trucks",
        powerImg, gloryImg, powerVer, gloryVer,
        message: "Updated home page truck images.",
        errorMsg: null,
      });
    } catch (err) {
      res.status(400).render("admin/home-trucks", {
        title: "Home trucks",
        powerImg: getSetting("home_truck_power_img") || "",
        gloryImg: getSetting("home_truck_glory_img") || "",
        powerVer: getSetting("home_truck_power_ver") || "",
        gloryVer: getSetting("home_truck_glory_ver") || "",
        message: null,
        errorMsg: err?.message || "Failed to update images",
      });
    }
  }
);

export default router;
