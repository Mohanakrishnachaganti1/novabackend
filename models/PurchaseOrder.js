import mongoose from "mongoose";

// Schema for individual items in a purchase order
const itemSchema = new mongoose.Schema({
  styleNo: { type: String, default: "" },
  description: { type: String, default: "Product" },
  color: { type: String, default: "" },
  size: { type: String, default: "" },
  qty: { type: Number, default: 1 },
  price: { type: Number, default: 0 },
  total: { type: Number, default: 0 }, 
  images: { type: [String], default: [] },
});

// Main Purchase Order Schema
const purchaseOrderSchema = new mongoose.Schema(
  {
    // Unique purchase order identifier shared across draft/order/confirmation
    purchaseOrderId: { type: String, required: true, unique: true },
    
    // Owner info (polymorphic: "User" or "Guest")
    ownerType: { type: String, enum: ["User", "Guest"], required: true },
    ownerId: { type: mongoose.Schema.Types.ObjectId, required: true },
    
    // Bank / Payment info (optional)
    bankName: { type: String },
    accountNo: { type: String },
    routingNo: { type: String },

    // Customer info
    customerName: { type: String },
    email: { type: String },
    attn: { type: String },
    address: { type: String },
    tel: { type: String },
    fax: { type: String },
    notes: { type: String },

    // Items array
    items: { type: [itemSchema], default: [] },

    // Shipping info for Stripe checkout
    shippingInfo: {
      name: { type: String },
      address: { type: String },
      city: { type: String },
      postalCode: { type: String },
      country: { type: String },
    },

    // Total order amount
    totalAmount: { type: Number, default: 0 },

    // Form data if any (like custom form values)
    form: { type: Object },

    // Stripe session ID after creating checkout session
    stripeSessionId: { type: String, default: "" },
  },
  { timestamps: true } // automatically adds createdAt and updatedAt
);

// Export the model
const PurchaseOrder = mongoose.model("PurchaseOrder", purchaseOrderSchema);
export default PurchaseOrder;
