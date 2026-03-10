import mongoose from "mongoose";
import slugify from "slugify";
import Product from "../models/Product.js";

const MONGO_URI = "YOUR_MONGODB_CONNECTION_STRING";

async function addSlugs() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("MongoDB connected");

    const products = await Product.find();

    for (const p of products) {
      if (!p.slug) {
        p.slug = slugify(p.name, { lower: true, strict: true });
        await p.save();
        console.log(`Slug added: ${p.slug}`);
      }
    }

    console.log("All slugs added");
    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

addSlugs();
