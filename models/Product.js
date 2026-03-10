import mongoose from "mongoose";

const ProductSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },
    price: Number,
    
    category: {
    type: String,
    required: true, // electronics, fashion, robots
    },
    subcategory: {
    type: String,   // fans, vacuum, clutches
    },
    colors: [String],
    slug: { type: String, unique: true },
    sizes: [String],
    minQty: Number,
    images: [String],
    description: String,
    // Professional variant system
    variants: [
      {
        color: { type: String },
        size: { type: String },
        image: { type: String },
        price: { type: Number },
        sku: { type: String },
        stock: { type: Number, default: 0 },
        active: { type: Boolean, default: true }
      }
    ]
  },
  { timestamps: true }
);

export default mongoose.model("Product", ProductSchema);
