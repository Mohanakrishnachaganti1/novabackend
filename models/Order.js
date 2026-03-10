import mongoose from "mongoose";

const orderSchema = new mongoose.Schema({
  items: Array,
  shippingInfo: Object,
  totalAmount: Number,
  form: Object,
  status: { type: String, default: "pending" },
  stripeSessionId: String,
}, { timestamps: true });

export default mongoose.model("Order", orderSchema);
