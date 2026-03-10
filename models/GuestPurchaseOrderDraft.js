import mongoose from "mongoose";

// Schema for individual items in a purchase order draft
const itemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  name: { type: String },
  price: { type: Number },
  qty: { type: Number, default: 1 },
  color: { type: String, default: null },
  size: { type: String, default: null },
});

// Guest Purchase Order Draft Schema
const guestPurchaseOrderDraftSchema = new mongoose.Schema(
  {
    guestId: { type: mongoose.Schema.Types.ObjectId, ref: "Guest", required: true },
    purchaseOrderId: { type: String, required: true, unique: true },
    items: { type: [itemSchema], default: [] },
  },
  { timestamps: true }
);

export default mongoose.model("GuestPurchaseOrderDraft", guestPurchaseOrderDraftSchema);
