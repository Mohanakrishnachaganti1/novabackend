import express from "express";
import Guest from "../models/Guest.js";
import crypto from "crypto";

const router = express.Router();

// Create a guest session
router.post("/", async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email) {
      return res.status(400).json({ error: "Name and email are required" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    // Generate a unique session ID for the guest
    const sessionId = crypto.randomBytes(32).toString("hex");

    // Create or find guest (if email already exists, return existing guest)
    let guest = await Guest.findOne({ email });
    if (!guest) {
      guest = new Guest({ name, email, sessionId });
      await guest.save();
    } else {
      // Update session ID for existing guest
      guest.sessionId = sessionId;
      await guest.save();
    }

    res.json({
      message: "Guest session created",
      guest: { _id: guest._id, name: guest.name, email: guest.email, sessionId: guest.sessionId },
    });
  } catch (err) {
    console.error("Guest creation error:", err);
    res.status(500).json({ error: "Failed to create guest session", details: err.message });
  }
});

// Get guest by ID
router.get("/:guestId", async (req, res) => {
  try {
    const guest = await Guest.findById(req.params.guestId);
    if (!guest) {
      return res.status(404).json({ error: "Guest not found" });
    }
    res.json({ guest });
  } catch (err) {
    console.error("Fetch guest error:", err);
    res.status(500).json({ error: "Failed to fetch guest" });
  }
});

export default router;
