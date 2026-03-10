import express from "express";
import PurchaseOrderDraft from "../models/PurchaseOrderDraft.js";
import Product from "../models/Product.js";
import crypto from "crypto";
import mongoose from "mongoose";
import authenticate from "../middleware/authenticate.js";

const router = express.Router();
// Flexible auth — required for Users, optional for Guests
function authenticateIfUser(req, res, next) {
  if (req.params.ownerType === "Guest") return next();
  return authenticate(req, res, next);
}
// Authorization check — verifies user owns the requested draft
function checkOwnership(req, res, ownerType, ownerId) {
  if (ownerType === "Guest") {
    return true;
  }
  if (ownerType === "User") {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return false;
    }
    if (req.user.id !== ownerId) {
      res.status(403).json({ error: "Forbidden — you can only access your own draft" });
      return false;
    }
  }
  return true;
}

/**
 * GET /:ownerType/:ownerId
 * Fetch or create a draft PO for a user or guest
 */
router.get("/:ownerType/:ownerId", authenticateIfUser, async (req, res) => {
  try {
    const { ownerType, ownerId } = req.params;

    if (!["User", "Guest"].includes(ownerType)) {
      return res.status(400).json({ error: "ownerType must be 'User' or 'Guest'" });
    }
    if (!checkOwnership(req, res, ownerType, ownerId)) return;

    // Convert string ownerId to ObjectId for MongoDB query
    const ownerIdObj = mongoose.Types.ObjectId.isValid(ownerId) 
      ? new mongoose.Types.ObjectId(ownerId)
      : ownerId;

    let po = await PurchaseOrderDraft.findOne({ ownerType, ownerId: ownerIdObj });
    if (!po) {
      const purchaseOrderId = crypto.randomBytes(16).toString("hex");
      po = new PurchaseOrderDraft({ ownerType, ownerId: ownerIdObj, purchaseOrderId, items: [] });
      await po.save();
    }

    res.json(po);
  } catch (err) {
    console.error("Error fetching PO draft:", err);
    res.status(500).json({ error: "Failed to fetch PO draft" });
  }
});

/**
 * POST /:ownerType/:ownerId/items
 * Add/update items in draft PO
 */
router.post("/:ownerType/:ownerId/items", authenticateIfUser, async (req, res) => {
  try {
    const { ownerType, ownerId } = req.params;
    const { items } = req.body;

    if (!["User", "Guest"].includes(ownerType)) {
      return res.status(400).json({ error: "ownerType must be 'User' or 'Guest'" });
    }
    if (!checkOwnership(req, res, ownerType, ownerId)) return;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Items array is required" });
    }

    // Convert string ownerId to ObjectId for MongoDB query
    const ownerIdObj = mongoose.Types.ObjectId.isValid(ownerId) 
      ? new mongoose.Types.ObjectId(ownerId)
      : ownerId;

    let po = await PurchaseOrderDraft.findOne({ ownerType, ownerId: ownerIdObj });
    if (!po) {
      const purchaseOrderId = crypto.randomBytes(16).toString("hex");
      // SECURITY FIX: Idempotency check — prevent duplicate orders
    const existingOrder = await PurchaseOrder.findOne({ purchaseOrderId });
    if (existingOrder) {
      return res.status(409).json({
        message: "Order already exists.",
        orderId: existingOrder._id,
      });
    }
      po = new PurchaseOrderDraft({ ownerType, ownerId: ownerIdObj, purchaseOrderId, items: [] });
      await po.save();
    }

    // merge items into a plain array then atomically replace
    const merged = [...po.items.map((i) => ({
      productId: i.productId,
      name: i.name,
      price: i.price,
      qty: i.qty,
      color: i.color,
      size: i.size,
      image: i.image,
    }))];

    // Fetch product images for new/updated items
    for (const item of items) {
      const idx = merged.findIndex(
        (i) => i.productId === item.productId && i.color === item.color && i.size === item.size
      );
      
      let image = item.image; // Use provided image if available
      if (!image) {
        // Fetch product to get first image
        try {
          const product = await Product.findById(item.productId);
          image = product?.images?.[0] || null;
        } catch (e) {
          console.error("Error fetching product image:", e);
        }
      }
      
      if (idx > -1) {
        merged[idx].qty = (Number(merged[idx].qty) || 0) + (Number(item.quantity) || 0);
      } else {
        merged.push({
          productId: item.productId,
          name: item.name,
          price: item.price,
          qty: Number(item.quantity) || 0,
          color: item.color || null,
          size: item.size || null,
          image: image,
        });
      }
    }

    const updated = await PurchaseOrderDraft.findOneAndUpdate(
      { ownerType, ownerId: ownerIdObj },
      { $set: { items: merged } },
      { new: true, upsert: true }
    );

    res.json({ message: "Order added successfully", po: updated });
  } catch (err) {
    console.error("Error adding items to PO:", err);
    res.status(500).json({ error: "Failed to update PO draft", details: err.message });
  }
});

/**
 * DELETE /:ownerType/:ownerId/items
 * Delete a single item from draft PO or clear all items
 */
router.delete("/:ownerType/:ownerId/items", authenticateIfUser, async (req, res) => {
  try {
    const { ownerType, ownerId } = req.params;
    const { productId, color, size } = req.body || {};

    if (!["User", "Guest"].includes(ownerType)) {
      return res.status(400).json({ error: "ownerType must be 'User' or 'Guest'" });
    }
    if (!checkOwnership(req, res, ownerType, ownerId)) return;

    // Convert string ownerId to ObjectId for MongoDB query
    const ownerIdObj = mongoose.Types.ObjectId.isValid(ownerId) 
      ? new mongoose.Types.ObjectId(ownerId)
      : ownerId;

    const po = await PurchaseOrderDraft.findOne({ ownerType, ownerId: ownerIdObj });
    if (!po) return res.status(404).json({ error: "Draft not found" });

    if (productId) {
      // Remove matching items (match productId + optional color + size)
      const newItems = po.items.filter(
        (i) => !(
          i.productId === productId &&
          (color ? i.color === color : true) &&
          (size ? i.size === size : true)
        )
      );

      if (newItems.length === po.items.length) {
        return res.status(404).json({ error: "Item not found in draft" });
      }

      const updated = await PurchaseOrderDraft.findOneAndUpdate(
        { ownerType, ownerId: ownerIdObj },
        { $set: { items: newItems } },
        { new: true }
      );

      return res.json({ message: "Item removed", po: updated });
    }

    // No productId -> clear all items
    const cleared = await PurchaseOrderDraft.findOneAndUpdate(
      { ownerType, ownerId: ownerIdObj },
      { $set: { items: [] } },
      { new: true }
    );
    return res.json({ message: "Draft cleared", po: cleared });
  } catch (err) {
    console.error("Error deleting items from PO:", err);
    res.status(500).json({ error: "Failed to delete items from PO" });
  }
});

export default router;
