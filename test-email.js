import dotenv from "dotenv";
import { sendPurchaseOrderNotification, sendPurchaseOrderToAdmin } from "./utils/mailer.js";

dotenv.config();

const testOrder = {
  purchaseOrderId: "TEST-EMAIL-001",
  customerName: "Test User",
  email: "test-recipient@example.com",
  items: [
    { styleNo: "NOVA-001", description: "Sample Product", color: "Blue", size: "M", qty: 2, price: 12.5, total: 25 },
  ],
  totalAmount: 25,
  shippingInfo: { name: "Test User", address: "123 Test St", city: "Testville", postalCode: "00000", country: "USA" },
  notes: "Test order",
  createdAt: new Date(),
};

(async () => {
  try {
    console.log("Starting test email send...");

    const customerEmail = process.env.TEST_CUSTOMER_EMAIL || testOrder.email;
    const adminEmail = process.env.TEST_ADMIN_EMAIL || process.env.SMTP_USER;

    if (!customerEmail) {
      console.error("No customer email available. Set TEST_CUSTOMER_EMAIL in .env or include email in testOrder.");
      process.exit(1);
    }

    if (!adminEmail) {
      console.error("No admin email available. Set TEST_ADMIN_EMAIL in .env or ensure SMTP_USER is set in .env.");
      process.exit(1);
    }

    const custRes = await sendPurchaseOrderNotification(customerEmail, testOrder);
    console.log("Customer send result:", custRes);

    const adminRes = await sendPurchaseOrderToAdmin(adminEmail, testOrder);
    console.log("Admin send result:", adminRes);

    console.log("Test email script finished.");
    process.exit(0);
  } catch (err) {
    console.error("Test email failed:", err);
    process.exit(1);
  }
})();
