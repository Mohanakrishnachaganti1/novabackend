import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import session from "express-session";
import MongoStore from "connect-mongo";
import connectDB from "./config/db.js";

// Routes
import authRoutes from "./routes/auth/index.js";
import uploadRoutes from "./routes/upload.js";
import productRoutes from "./routes/product.js";
import purchaseOrderRoute from "./routes/purchaseOrder.js";
import purchaseOrderDraftRoutes from "./routes/purchaseOrderDraft.js";
import signupRouter from "./routes/auth/signup.js";
import paymentRoutes from "./routes/payment.js";
import webhookRoutes from "./routes/webhook.js";
import guestRoutes from "./routes/guests.js";
import ordersRoutes from "./routes/orders.js";
import Stripe from "stripe";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Load environment variables
dotenv.config();
const env = process.env.NODE_ENV || "development";
console.log("NODE_ENV:", env);
console.log("Cookie secure:", env === "production");
console.log("Cookie sameSite:", env === "production" ? "none" : "lax");
const app = express();

// Connect to database
connectDB();

// Middleware
app.use(express.json());

// SECURITY FIX: helmet — sets security headers, removes X-Powered-By
app.use(helmet());

// CORS
const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://10.73.121.103:5173",
  "https://lucky-torrone-f23027.netlify.app",
  "https://www.novainternationaldesigns.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Session
app.use(
  session({
    name: "nova.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
      httpOnly: true,
      secure: env === "production",
      sameSite: env === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// Routes
// SECURITY FIX: Rate limiting on login — max 5 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many login attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/auth/login", loginLimiter);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/upload", uploadRoutes);
app.use("/api/products", productRoutes);
app.use("/api/purchase-order", purchaseOrderRoute);
app.use("/api/purchaseOrderDraft", purchaseOrderDraftRoutes);
app.use("/api/guests", guestRoutes);
app.use("/api/orders", ordersRoutes);

// Payment and Webhook Routes
app.use("/api/webhook", webhookRoutes);
app.use("/api/payment", paymentRoutes);

// Add signup route
app.use("/api/signup", signupRouter);

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mongoState: mongoose.connection.readyState,
  });
});

// Root
app.get("/", (req, res) => {
  res.send("Backend is running...");
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    }

    res.clearCookie("nova.sid", {
      httpOnly: true,
      sameSite: env === "production" ? "none" : "lax",
      secure: env === "production",
    });

    res.json({ message: "Logged out successfully" });
  });
});

// stripe test endpoint

app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount,
      currency: 'usd',
    });
    res.status(200).send({
      clientSecret: paymentIntent.client_secret,
    });
 } catch (err) {
    console.error("Payment intent error:", err);
    res.status(500).json({ error: "Payment processing failed." });
  }
});
// Server
// =====================================================
// SECURITY FIX: Global error handler — prevent stack trace exposure
// Logs full error internally, returns generic message to client
// =====================================================
app.use((err, req, res, next) => {
  console.error("[Global Error Handler]", err.stack);
  if (process.env.NODE_ENV === "production") {
    return res.status(500).json({ message: "Something went wrong." });
  }
  return res.status(500).json({ message: err.message });
});

// Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});