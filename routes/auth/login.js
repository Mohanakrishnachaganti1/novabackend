// src/routes/auth/login.js
import express from 'express';
import bcrypt from 'bcryptjs';
import User from '../../models/User.js';

const router = express.Router();

// POST /api/auth/login
router.post("/", async (req, res) => {
  const { email, password } = req.body;

  // SECURITY FIX: Reject non-string inputs — prevents NoSQL injection + server crash
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "Invalid input format." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Session setup
    req.session.userId = user._id;  // Save session

    res.json({
      message: "Login successful",
      user: { _id: user._id, name: user.name, email: user.email, role: user.role || 'buyer' }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
