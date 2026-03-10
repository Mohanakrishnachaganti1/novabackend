// routes/cart.js
import express from "express";
import User from "../models/User.js";

const router = express.Router();

// Add item to cart
router.post("/add", async (req, res) => {
  const { userId, productId, quantity } = req.body;
  try {
    const user = await User.findById(userId);
    const cartItemIndex = user.cart.findIndex(item => item.productId.toString() === productId);

    if (cartItemIndex >= 0) {
      // If the item exists, update the quantity
      user.cart[cartItemIndex].quantity += quantity;
    } else {
      // If item doesn't exist, add to cart
      user.cart.push({ productId, quantity });
    }

    await user.save();
    res.status(200).json({ cart: user.cart });
  } catch (err) {
    res.status(500).json({ message: "Error adding item to cart" });
  }
});

// Get user's cart
router.get("/", async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).populate("cart.productId");
    res.status(200).json({ cart: user.cart });
  } catch (err) {
    res.status(500).json({ message: "Error fetching cart" });
  }
});

export default router;
