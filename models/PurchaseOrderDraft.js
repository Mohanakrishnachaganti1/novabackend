import mongoose from "mongoose";

const draftItemSchema = new mongoose.Schema({
  productId: String,
  name: String,
  price: Number,
  qty: Number,
  color: { type: String, default: null },
  size: { type: String, default: null },
  image: { type: String, default: null }, // Thumbnail image URL
});

const purchaseOrderDraftSchema = new mongoose.Schema({
  ownerType: { type: String, enum: ["User", "Guest"], required: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true },
  purchaseOrderId: { type: String, required: true, unique: true },
  items: [draftItemSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Compound index for efficient queries by ownerType + ownerId
purchaseOrderDraftSchema.index({ ownerType: 1, ownerId: 1 }, { unique: true });

export default mongoose.model("PurchaseOrderDraft", purchaseOrderDraftSchema);
