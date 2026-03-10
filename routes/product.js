import express from "express";
import Product from "../models/Product.js";

const router = express.Router();

/**
 * GET PRODUCTS
 * Examples:
 * /api/products
 * /api/products?category=fashion
 * /api/products?category=fashion&subcategory=men
 */
router.get("/", async (req, res) => {
  try {
    const { category, subcategory } = req.query;

    let filter = {};

    if (category) filter.category = new RegExp(`^${category}$`, "i");
    if (subcategory) filter.subcategory = new RegExp(`^${subcategory}$`, "i");

    const products = await Product.find(filter);
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/**
 * GET PRODUCT BY ID
 */
router.get("/id/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json(product);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/**
 * GET PRODUCT BY SLUG
 */
router.get("/slug/:slug", async (req, res) => {
  try {
    const product = await Product.findOne({ slug: req.params.slug });
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json(product);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

export default router;
