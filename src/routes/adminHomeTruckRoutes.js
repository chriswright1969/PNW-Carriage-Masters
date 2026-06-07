// /src/routes/adminHomeTruckRoutes.js
import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";

import { requireAdmin } from "../middleware.js";
import { getSetting, setSetting } from "../db.js";

const router = express.Router();

const uploadDir = process.env.UPLOAD_DIR || "/var/data/uploads";
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(ext) ? ext : ".jpg";
    cb(null, `home-truck-${Date.now()}-${crypto.randomBytes(6).toString("hex")}${safeExt}`);
  },
});

const allowed = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB
  fileFilter: (_req, file, cb) => {
    if (!allowed.has(file.mimetype)) {
      return cb(new Error("Only JPG/PNG/WEBP/GIF allowed"));
    }
    cb(null, true);
  },
});

function nowVer() {
  return String(Date.now());
}

function getHomeTruckImageSettings() {
  return {
    powerImg: getSetting("home_truck_power_img") || "",
    powerVer: getSetting("home_truck_power_ver") || "",

    gloryImg: getSetting("home_truck_glory_img") || "",
    gloryVer: getSetting("home_truck_glory_ver") || "",

    scaniaImg: getSetting("home_truck_scania_img") || "",
    scaniaVer: getSetting("home_truck_scania_ver") || "",
  };
}

router.get("/home-trucks", requireAdmin, (_req, res) => {
  res.render("admin/home-trucks", {
    title: "Home trucks",
    ...getHomeTruckImageSettings(),
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
    { name: "scania_img", maxCount: 1 },
  ]),
  (req, res) => {
    try {
      let {
        powerImg,
        powerVer,
        gloryImg,
        gloryVer,
        scaniaImg,
        scaniaVer,
      } = getHomeTruckImageSettings();

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

      if (req.body?.clear_scania === "1") {
        setSetting("home_truck_scania_img", "");
        setSetting("home_truck_scania_ver", nowVer());
        scaniaImg = "";
        scaniaVer = getSetting("home_truck_scania_ver") || "";
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

      if (req.files?.scania_img?.[0]) {
        scaniaImg = req.files.scania_img[0].filename;
        scaniaVer = nowVer();

        setSetting("home_truck_scania_img", scaniaImg);
        setSetting("home_truck_scania_ver", scaniaVer);
      }

      return res.render("admin/home-trucks", {
        title: "Home trucks",
        powerImg,
        powerVer,
        gloryImg,
        gloryVer,
        scaniaImg,
        scaniaVer,
        message: "Updated home page truck images.",
        errorMsg: null,
      });
    } catch (err) {
      console.error("Home truck image update failed:", err);

      return res.status(400).render("admin/home-trucks", {
        title: "Home trucks",
        ...getHomeTruckImageSettings(),
        message: null,
        errorMsg: err?.message || "Failed to update images",
      });
    }
  }
);

export default router;
