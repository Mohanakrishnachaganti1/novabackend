// import express from "express";
// import Stripe from "stripe";
// import PurchaseOrder from "../models/PurchaseOrder.js";

// const router = express.Router();
// const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// router.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
//   const sig = req.headers["stripe-signature"];
//   let event;

//   try {
//     event = stripe.webhooks.constructEvent(
//       req.body,
//       sig,
//       process.env.STRIPE_WEBHOOK_SECRET
//     );
//   } catch (err) {
//     console.error("Webhook signature error:", err.message);
//     return res.status(400).send(`Webhook Error`);
//   }

//   if (event.type === "checkout.session.completed") {
//     const session = event.data.object;

//     // Update order status
//     await PurchaseOrder.findByIdAndUpdate(session.metadata.orderId, {
//       status: "paid"
//     });
//   }

//   res.json({ received: true });
// });

// export default router;
