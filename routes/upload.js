// /routes/upload.js
import express from "express";
import multer from "multer";
import cloudinary from "../config/cloudinary.js";
import authenticate from "../middleware/authenticate.js";
import fs from "fs";

const router = express.Router();

// SECURITY FIX: Whitelist allowed image MIME types only
const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp", "image/gif"];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

const upload = multer({
  dest: "uploads/",
  limits: {
    fileSize: MAX_FILE_SIZE,
  },
 fileFilter: (req, file, cb) => {
    const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp", ".gif"];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf("."));

    const mimeOk = ALLOWED_TYPES.includes(file.mimetype);
    const extOk = ALLOWED_EXTENSIONS.includes(ext);

    if (mimeOk && extOk) {
      cb(null, true);
    } else {
      cb(new Error("INVALID_FILE_TYPE"), false);
    }
  },
});

// SECURITY FIX: authenticate + multer error handling via callback pattern
router.post("/", authenticate, (req, res) => {
  upload.single("image")(req, res, async (err) => {

    // Handle multer errors before anything else
    if (err) {
      if (req.file && req.file.path) fs.unlink(req.file.path, () => {});
      if (err.message === "INVALID_FILE_TYPE") {
        return res.status(400).json({
          message: "Invalid file type. Only JPEG, PNG, WebP, and GIF are allowed.",
        });
      }
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          message: "File too large. Maximum size is 5MB.",
        });
      }
      console.error("Upload error:", err);
      return res.status(500).json({ message: "Upload failed." });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded." });
      }

      const result = await cloudinary.uploader.upload(req.file.path);

      // SECURITY FIX: Always clean up temp file after Cloudinary upload
      fs.unlink(req.file.path, (unlinkErr) => {
        if (unlinkErr) console.error("Temp file cleanup error:", unlinkErr.message);
      });

      res.json({ imageUrl: result.secure_url });
    } catch (uploadErr) {
      if (req.file && req.file.path) fs.unlink(req.file.path, () => {});
      console.error("Cloudinary upload error:", uploadErr);
      res.status(500).json({ message: "Upload failed." });
    }
  });
});

export default router;