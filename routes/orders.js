import express from "express";
import PurchaseOrder from "../models/PurchaseOrder.js";
import User from "../models/User.js";
import Guest from "../models/Guest.js";
import authenticate from "../middleware/authenticate.js";
import requireAdmin from "../middleware/requireAdmin.js";

const router = express.Router();

/**
 * GET ALL ORDERS FOR A LOGGED-IN USER
 * GET /api/orders/my-orders
 * Requires session/authentication
 */
router.get("/my-orders",authenticate,async (req, res) => {
  try {
    
    // Query by new schema (ownerType/ownerId) or fallback to old schema (userId)
    const orders = await PurchaseOrder.find({
      $or: [
        { ownerType: "User", ownerId: req.session.userId },
        { userId: req.session.userId } // fixed: explicitly using req.session.userId
      ]
    })
      .sort({ createdAt: -1 })
      .populate("userId", "name email");

    res.json({ orders, count: orders.length });
  } catch (err) {
    console.error("Error fetching user orders:", err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

/**
 * GET ALL ORDERS FOR A GUEST BY GUEST ID
 * GET /api/orders/guest/:guestId
 */ 
router.get("/guest/:guestId", authenticate, async (req, res) => {
  try {
    const { guestId } = req.params;
    // Guests can only access their own orders
// For guest routes we check session guestId if available
if (req.session.guestId && req.session.guestId.toString() !== guestId) {
  return res.status(403).json({ error: "Forbidden — you can only access your own orders" });
}

    // Fetch guest details
    const guest = await Guest.findById(guestId);
    if (!guest) {
      return res.status(404).json({ error: "Guest not found" });
    }

    // Fetch all orders for this guest using new schema or fallback to old schema
    const orders = await PurchaseOrder.find({
      $or: [
        { ownerType: "Guest", ownerId: guestId },
        { guestId: guestId } // fixed
      ]
    })
      .sort({ createdAt: -1 });

    res.json({
      guest: { _id: guest._id, name: guest.name, email: guest.email },
      orders,
      count: orders.length
    });
  } catch (err) {
    console.error("Error fetching guest orders:", err);
    res.status(500).json({ error: "Failed to fetch guest orders" });
  }
});

/**
 * GET USER PROFILE WITH ALL ORDERS
 * GET /api/orders/user/:userId
 */
router.get("/user/:userId", authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    // User can only access their own orders unless they are admin
if (req.user.id !== userId) {
  return res.status(403).json({ error: "Forbidden — you can only access your own orders" });
}

    // Fetch user details
    const user = await User.findById(userId).select("-password");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Fetch all orders for this user using new schema or fallback to old schema
    const orders = await PurchaseOrder.find({
      $or: [
        { ownerType: "User", ownerId: userId },
        { userId: userId } // fixed
      ]
    })
      .sort({ createdAt: -1 });

    res.json({
      user: { _id: user._id, name: user.name, email: user.email },
      orders,
      count: orders.length
    });
  } catch (err) {
    console.error("Error fetching user orders:", err);
    res.status(500).json({ error: "Failed to fetch user orders" });
  }
});

/**
 * GET SINGLE ORDER BY ORDER ID
 * GET /api/orders/:orderId
 */
router.get("/:orderId", authenticate, async (req, res) => {
  try {
    const { orderId } = req.params;

    const order = await PurchaseOrder.findById(orderId)
      .populate("userId", "name email")
      .populate("guestId", "name email");

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }
    // Verify the requesting user owns this order
const orderOwnerId = order.ownerId ? order.ownerId.toString() : order.userId?.toString();
if (orderOwnerId !== req.user.id) {
  return res.status(403).json({ error: "Forbidden — you can only access your own orders" });
}

    res.json({ order });
  } catch (err) {
    console.error("Error fetching order:", err);
    res.status(500).json({ error: "Failed to fetch order" });
  }
});

/**
 * SEARCH ORDERS BY EMAIL (for both users and guests)
 * GET /api/orders/search/:email
 */
router.get("/search/:email", authenticate, requireAdmin, async (req, res) => {
  try {
    const { email } = req.params;

    // Search for orders by email in multiple fields (handles both old and new schema)
    const allOrders = await PurchaseOrder.find({
      $or: [
        { email: { $regex: email, $options: "i" } }, // old user email
        { guestEmail: { $regex: email, $options: "i" } } // old guest email
      ]
    }).sort({ createdAt: -1 });

    res.json({
      orders: allOrders,
      count: allOrders.length
    });
  } catch (err) {
    console.error("Error searching orders:", err);
    res.status(500).json({ error: "Failed to search orders" });
  }
});

export default router;
