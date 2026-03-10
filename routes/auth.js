// routes/auth.js
import express from "express";
import bcrypt from "bcryptjs";
import User from "../models/User.js";

const router = express.Router();

// Sign In
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    req.session.userId = user._id;  // Set user session
    res.json({ user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Logout
router.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Logout failed" });
    res.clearCookie("connect.sid");  // Clear session cookie
    res.json({ message: "Logged out" });
  });
});

// Get current user
router.get("/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: "Unauthorized" });
  User.findById(req.session.userId).then(user => {
    res.json({ user: { id: user._id, name: user.name, email: user.email } });
  });
});

export default router;
