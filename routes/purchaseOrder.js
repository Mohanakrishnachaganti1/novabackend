// purchaseorder.js
import express from "express";
import crypto from "crypto";
import mongoose from "mongoose";
import PurchaseOrder from "../models/PurchaseOrder.js";
import PurchaseOrderDraft from "../models/PurchaseOrderDraft.js";
import User from "../models/User.js";
import Guest from "../models/Guest.js";
import sanitizeHtml from "sanitize-html";
import authenticate from "../middleware/authenticate.js";
import requireAdmin from "../middleware/requireAdmin.js";

const router = express.Router();
// GET all orders — admin only
router.get("/", authenticate, requireAdmin, async (req, res) => {
  try {
    const orders = await PurchaseOrder.find().sort({ createdAt: -1 }).lean();
    res.json({ orders });
  } catch (err) {
    console.error("Admin orders fetch error:", err);
    res.status(500).json({ message: "Failed to fetch orders." });
  }
});

// Helper — strip all HTML tags from a string
const sanitize = (val) =>
  typeof val === "string"
    ? sanitizeHtml(val, { allowedTags: [], allowedAttributes: {} }).trim()
    : val;

// Create new purchase order
router.post("/", authenticate, async (req, res) => {
  try {
    const {
      email,
      userId,
      guestId,
      purchaseOrderId: incomingPOId,
      ownerType,
      ownerId,
    } = req.body;

    // Validate email if provided
    let recipientEmail = email;
    if (recipientEmail) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(String(recipientEmail).toLowerCase())) {
        return res.status(400).json({ error: "Invalid email format" });
      }
    }

    // Determine final owner type & ID
    let finalOwnerType = ownerType;
    let finalOwnerId = ownerId;
    if (!finalOwnerType || !finalOwnerId) {
      if (userId) {
        finalOwnerType = "User";
        finalOwnerId = userId;
      } else if (guestId) {
        finalOwnerType = "Guest";
        finalOwnerId = guestId;
      } else {
        return res.status(400).json({ error: "Either userId or guestId must be provided" });
      }
    }

    if (!["User", "Guest"].includes(finalOwnerType)) {
      return res.status(400).json({ error: "ownerType must be 'User' or 'Guest'" });
    }

    // Determine purchaseOrderId
    let purchaseOrderId = incomingPOId;
    if (!purchaseOrderId) {
      const ownerIdObj = mongoose.Types.ObjectId.isValid(finalOwnerId)
        ? new mongoose.Types.ObjectId(finalOwnerId)
        : finalOwnerId;
      const draft = await PurchaseOrderDraft.findOne({
        ownerType: finalOwnerType,
        ownerId: ownerIdObj,
      });
      if (draft && draft.purchaseOrderId) purchaseOrderId = draft.purchaseOrderId;
    }
    if (!purchaseOrderId) purchaseOrderId = crypto.randomBytes(16).toString("hex");

    // Clean empty-string top-level fields
    const cleaned = {};
    Object.keys(req.body || {}).forEach((k) => {
      const v = req.body[k];
      if (v === null || v === undefined) return;
      if (typeof v === "string" && v.trim() === "") return;
      cleaned[k] = v;
    });

    // Remove empty strings inside nested objects like form & shippingInfo
    ["form", "shippingInfo"].forEach((field) => {
      if (cleaned[field] && typeof cleaned[field] === "object") {
        Object.keys(cleaned[field]).forEach((k) => {
          if (typeof cleaned[field][k] === "string" && cleaned[field][k].trim() === "") {
            delete cleaned[field][k];
          }
        });
        if (Object.keys(cleaned[field]).length === 0) delete cleaned[field];
      }
    });

    // =====================================================
    // SECURITY FIX: Sanitize all string fields — prevent Stored XSS
    // Strips all HTML tags from top-level and nested string fields
    // =====================================================
    Object.keys(cleaned).forEach((k) => {
      if (typeof cleaned[k] === "string") {
        cleaned[k] = sanitize(cleaned[k]);
      } else if (cleaned[k] && typeof cleaned[k] === "object" && !Array.isArray(cleaned[k])) {
        Object.keys(cleaned[k]).forEach((nested) => {
          if (typeof cleaned[k][nested] === "string") {
            cleaned[k][nested] = sanitize(cleaned[k][nested]);
          }
        });
      }
    });

    // =====================================================
    // SECURITY FIX: Price validation against draft
    // Never trust prices from client — verify against draft
    // =====================================================
    if (cleaned.items && Array.isArray(cleaned.items) && cleaned.items.length > 0) {
      try {
        const ownerIdObj = mongoose.Types.ObjectId.isValid(finalOwnerId)
          ? new mongoose.Types.ObjectId(finalOwnerId)
          : finalOwnerId;

        const draft = await PurchaseOrderDraft.findOne({
          ownerType: finalOwnerType,
          ownerId: ownerIdObj,
        });

        if (draft && draft.items && draft.items.length > 0) {
          // Replace client-sent prices with trusted draft prices
          cleaned.items = cleaned.items.map((item) => {
            const draftItem = draft.items.find(
              (d) =>
                d.productId === item.productId &&
                (d.color || null) === (item.color || null) &&
                (d.size || null) === (item.size || null)
            );

            if (draftItem) {
              return {
                ...item,
                price: draftItem.price,
                total: draftItem.price * (item.qty || draftItem.qty || 1),
              };
            }

            console.warn(`[Security] Item not found in draft: ${item.productId}`);
            return item;
          });

          // Recalculate total from verified prices
          cleaned.totalAmount = cleaned.items.reduce(
            (sum, item) => sum + (item.price || 0) * (item.qty || 1),
            0
          );

          console.log(`[Security] Prices verified against draft for order ${purchaseOrderId}`);
        } else {
          // No draft found — block order with items to prevent price manipulation
          return res.status(400).json({
            error: "Order validation failed",
            details: "No purchase order draft found. Please add items to your cart first.",
          });
        }
      } catch (priceErr) {
        console.error("Price validation error:", priceErr);
      }
    }

    // Reject items with zero or negative prices
    if (cleaned.items && Array.isArray(cleaned.items)) {
      const invalidItems = cleaned.items.filter(
        (item) => !item.price || item.price <= 0
      );
      if (invalidItems.length > 0) {
        return res.status(400).json({
          error: "Invalid item prices detected",
          details: "All items must have a price greater than 0",
        });
      }
    }

    // =====================================================
    // Lookup email from User or Guest if not provided
    // =====================================================
    if (!recipientEmail) {
      try {
        if (finalOwnerType === "User") {
          const userDoc = await User.findById(finalOwnerId).select("email name").lean();
          if (userDoc && userDoc.email) {
            recipientEmail = userDoc.email;
            if (!cleaned.customerName && userDoc.name) cleaned.customerName = userDoc.name;
          }
        } else if (finalOwnerType === "Guest") {
          const guestDoc = await Guest.findById(finalOwnerId).select("email name").lean();
          if (guestDoc && guestDoc.email) {
            recipientEmail = guestDoc.email;
            if (!cleaned.customerName && guestDoc.name) cleaned.customerName = guestDoc.name;
          }
        }
      } catch (err) {
        console.warn("Email lookup error:", err.message);
      }
    }

    const orderData = {
      ...cleaned,
      email: recipientEmail,
      purchaseOrderId,
      ownerType: finalOwnerType,
      ownerId: mongoose.Types.ObjectId.isValid(finalOwnerId)
        ? new mongoose.Types.ObjectId(finalOwnerId)
        : finalOwnerId,
      paymentStatus: "pending",
    };

    // Save order with retry logic for unique purchaseOrderId
    let order = null;
    const maxRetries = 5;
    let attempt = 0;
    while (attempt < maxRetries) {
      try {
        order = new PurchaseOrder({ ...orderData });
        await order.save();
        break;
      } catch (e) {
        if (e.code === 11000 && e.keyPattern && e.keyPattern.purchaseOrderId) {
          attempt++;
          purchaseOrderId = crypto.randomBytes(16).toString("hex");
          orderData.purchaseOrderId = purchaseOrderId;
          continue;
        }
        throw e;
      }
    }

    if (!order) throw new Error("Failed to save order after multiple attempts");

    // ✅ DO NOT send email here — will send after Stripe payment
    res.json({ message: "Order saved successfully", order });
  } catch (error) {
    console.error("PurchaseOrder save error:", error);
    res.status(500).json({ error: "Failed to save order", details: error.message });
  }
});

export default router;