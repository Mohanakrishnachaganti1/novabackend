// routes/auth/me.js
import express from "express";
import User from "../../models/User.js";

const router = express.Router();

// GET /api/auth/me
router.get("/", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const user = await User.findById(req.session.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      user: {
        _id: user._id,       // Use _id for consistency with MongoDB
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Fetch user error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
