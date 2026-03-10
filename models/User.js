// models/User.js
import mongoose from "mongoose";

const CartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, required: true, default: 1 },
});

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "buyer" },
    cart: { type: [CartItemSchema], default: [] }, // Store the cart items here
    isPaid: { type: Boolean, default: false },
    paymentId: String,
  },
  { timestamps: true }
);  

export default mongoose.model("User", UserSchema);
