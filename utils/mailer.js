import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

// Create transporter - Gmail SMTP
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === "true" ? true : false, // false for TLS 587, true for SSL 465
  auth: {
    user: process.env.SMTP_USER,     // Gmail address
    pass: process.env.SMTP_PASS,     // Gmail app password or password
  },
  logger: false,
  debug: false,
});

// Optional: Verify SMTP connection
transporter.verify((err, success) => {
  if (success) {
    console.log(" Email service connected - Gmail SMTP Ready");
  } else {
    console.error(" mail service failed:", err ? err.message : "Unknown error");
    console.error("  Check your Gmail credentials in .env file");
    console.error("  SMTP_USER:", process.env.SMTP_USER);
    console.error("  SMTP_PASS length:", process.env.SMTP_PASS ? process.env.SMTP_PASS.length : "NOT SET");
  }
});

/**
 * Send a welcome email
 * @param {string} email - Recipient email
 * @param {string} name - Recipient name
 */
export const sendWelcomeEmail = async (email, name) => {
  try {
    await transporter.sendMail({
      from: `"Nova International" <${process.env.SMTP_USER}>`, // sender
      to: email,                                            // recipient
      subject: "Welcome to Nova International!",           // email subject
      html: `<p>Hello <strong>${name}</strong>, welcome to Nova International!</p>`, // email body
    });

    console.log("Email sent to", email);
  } catch (err) {
    console.error("Email sending failed:", err.message);
  }
};

/**
 * Send purchase order confirmation email
 * @param {string} email - Recipient email
 * @param {Object} orderData - Purchase order data
 */
export const sendPurchaseOrderConfirmation = async (email, orderData) => {
  try {
    const {
      purchaseOrderId,
      customerName,
      items = [],
      totalAmount,
      shippingInfo,
      notes,
      createdAt,
    } = orderData;

    // Format date
    const orderDate = createdAt
      ? new Date(createdAt).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
      : new Date().toLocaleDateString();

    // Build items HTML
    let itemsHTML = items
      .map(
        (item) =>
          `
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #eee;">
          <strong>${item.styleNo || "N/A"}</strong> - ${item.description}
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center;">
          ${item.color || "-"}
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center;">
          ${item.size || "-"}
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center;">
          ${item.qty}
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center;">
          $${item.price.toFixed(2)}
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right; font-weight: bold;">
          $${(item.total || item.qty * item.price).toFixed(2)}
        </td>
      </tr>
    `
      )
      .join("");

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
          }
          .container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            background-color: #ffffff;
            padding: 30px;
            border-bottom: 2px solid #667eea;
            text-align: center;
          }
          .header h1 {
            color: #667eea;
            margin: 0;
            font-size: 28px;
          }
          .header p {
            color: #666;
            margin: 5px 0 0 0;
          }
          .content {
            background-color: #ffffff;
            padding: 30px;
          }
          .section {
            margin-bottom: 30px;
          }
          .section h2 {
            color: #667eea;
            font-size: 16px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 15px;
          }
          .order-info {
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
            margin-bottom: 15px;
          }
          .order-info p {
            margin: 5px 0;
          }
          .info-label {
            font-weight: bold;
            color: #667eea;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
          }
          th {
            background-color: #667eea;
            color: white;
            text-align: left;
            padding: 12px;
            font-weight: bold;
          }
          .total-section {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
          }
          .total-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 16px;
          }
          .total-amount {
            font-size: 20px;
            font-weight: bold;
            color: #667eea;
            border-top: 2px solid #667eea;
            padding-top: 10px;
          }
          .footer {
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #eee;
          }
          .contact-info {
            color: #667eea;
            font-weight: bold;
          }
          .shipping-block {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Purchase Order Received</h1>
            <p>Thank you for your order with Nova International Designs</p>
          </div>

          <div class="content">
            <!-- Order Confirmation -->
            <div class="section">
              <h2>Order Confirmation</h2>
              <div class="order-info">
                <p><span class="info-label">Purchase Order ID:</span> <strong>${purchaseOrderId}</strong></p>
                <p><span class="info-label">Order Date:</span> ${orderDate}</p>
                <p><span class="info-label">Customer Name:</span> ${customerName || "N/A"}</p>
              </div>
            </div>

            <!-- Order Items -->
            <div class="section">
              <h2>Order Items</h2>
              <table>
                <thead>
                  <tr>
                    <th>Product</th>
                    <th>Color</th>
                    <th>Size</th>
                    <th>Quantity</th>
                    <th>Price</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  ${itemsHTML}
                </tbody>
              </table>
              <div class="total-section">
                <div class="total-row">
                  <span><strong>Order Total:</strong></span>
                  <span style="font-weight: bold; color: #667eea; font-size: 18px;">$${totalAmount.toFixed(2)}</span>
                </div>
              </div>
            </div>

            <!-- Shipping Information -->
            ${shippingInfo ? `
            <div class="section">
              <h2>Shipping Address</h2>
              <div class="shipping-block">
                <p><strong>${shippingInfo.name || "N/A"}</strong></p>
                <p>${shippingInfo.address || "N/A"}</p>
                <p>${shippingInfo.city || ""} ${shippingInfo.postalCode || ""}</p>
                <p>${shippingInfo.country || ""}</p>
              </div>
            </div>
            ` : ""}

            <!-- Additional Notes -->
            ${notes ? `
            <div class="section">
              <h2>Special Notes</h2>
              <div class="shipping-block">
                <p>${notes}</p>
              </div>
            </div>
            ` : ""}

            <!-- Next Steps -->
            <div class="section">
              <h2>What's Next?</h2>
              <p>
                Your purchase order has been successfully received. Our team will review your order and 
                contact you shortly to confirm the details and provide shipping information.
              </p>
              <p>
                If you have any questions, please don't hesitate to contact us at 
                <span class="contact-info">shila@novainternaionaldesigns.com</span> 
                or call us during business hours.
              </p>
            </div>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Nova International Designs. All rights reserved.</p>
            <p>
              <strong>Nova International Designs</strong><br>
              Email: <span class="contact-info">shila@novainternaionaldesigns.com</span>
            </p>
            <p style="color: #999; margin-top: 15px;">
              This is an automated email. Please do not reply directly to this message.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    await transporter.sendMail({
      from: `"Nova International Designs" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `Purchase Order Confirmation - Order #${purchaseOrderId}`,
      html: htmlContent,
    });

    console.log("Purchase order confirmation email sent to", email);
    return true;
  } catch (err) {
    console.error("Failed to send purchase order email:", err.message);
    return false;
  }
};

/**
 * Send payment confirmation email
 * @param {string} email - Recipient email
 * @param {Object} paymentData - Payment data
 */
export const sendPaymentConfirmationEmail = async (email, paymentData) => {
  try {
    const {
      purchaseOrderId,
      customerName,
      totalAmount,
    } = paymentData;

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
          }
          .container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            background-color: #ffffff;
            padding: 30px;
            border-bottom: 2px solid #667eea;
            text-align: center;
          }
          .header h1 {
            color: #28a745;
            margin: 0;
            font-size: 28px;
          }
          .header p {
            color: #666;
            margin: 5px 0 0 0;
          }
          .content {
            background-color: #ffffff;
            padding: 30px;
          }
          .section {
            margin-bottom: 30px;
          }
          .section h2 {
            color: #667eea;
            font-size: 16px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 15px;
          }
          .success-box {
            background: #d4edda;
            border: 2px solid #28a745;
            border-radius: 4px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
          }
          .success-box p {
            color: #155724;
            font-size: 16px;
            margin: 0;
          }
          .order-info {
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
            margin-bottom: 15px;
          }
          .order-info p {
            margin: 8px 0;
          }
          .info-label {
            font-weight: bold;
            color: #667eea;
          }
          .amount-display {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
            margin: 20px 0;
          }
          .amount-display p {
            margin: 0;
            color: #666;
          }
          .amount-display .amount {
            font-size: 32px;
            font-weight: bold;
            color: #28a745;
            margin-top: 10px;
          }
          .footer {
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #eee;
          }
          .contact-info {
            color: #667eea;
            font-weight: bold;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Payment Confirmed</h1>
            <p>Your payment has been successfully processed</p>
          </div>

          <div class="content">
            <!-- Success Message -->
            <div class="success-box">
              <p>Thank you for your purchase! Your payment has been received and confirmed.</p>
            </div>

            <!-- Order Summary -->
            <div class="section">
              <h2>Order Summary</h2>
              <div class="order-info">
                <p><span class="info-label">Order ID:</span> <strong>${purchaseOrderId}</strong></p>
                <p><span class="info-label">Customer Name:</span> ${customerName || "N/A"}</p>
                <p><span class="info-label">Payment Status:</span> <strong style="color: #28a745;">✓ Paid</strong></p>
              </div>
              <div class="amount-display">
                <p>Total Amount Paid</p>
                <div class="amount">$${totalAmount.toFixed(2)}</div>
              </div>
            </div>

            <!-- What Happens Next -->
            <div class="section">
              <h2>What Happens Next?</h2>
              <p>
                Our team has received your payment confirmation. You can expect:
              </p>
              <ul style="color: #555; line-height: 1.8;">
                <li><strong>Order Processing:</strong> Your order is now being prepared for shipping</li>
                <li><strong>Tracking Update:</strong> You'll receive a shipping update with tracking information soon</li>
                <li><strong>Delivery:</strong> Your items will be shipped according to the agreed delivery terms</li>
              </ul>
            </div>

            <!-- Support -->
            <div class="section">
              <h2>Questions?</h2>
              <p>
                If you have any questions about your order or payment, please don't hesitate to contact us:
              </p>
              <p>
                <strong>Email:</strong> <span class="contact-info">shilpa@novainternaionaldesigns.com</span><br>
                <strong>Hours:</strong> Monday-Friday, 9AM-5PM EST
              </p>
            </div>
          </div>

          <div class="footer">
            <p>© ${new Date().getFullYear()} Nova International Designs. All rights reserved.</p>
            <p>
              <strong>Nova International Designs</strong><br>
              Email: <span class="contact-info">shilpa@novainternaionaldesigns.com</span>
            </p>
            <p style="color: #999; margin-top: 15px;">
              This is an automated email. Please do not reply directly to this message.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    await transporter.sendMail({
      from: `"Nova International Designs" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `Payment Confirmation - Order #${purchaseOrderId}`,
      html: htmlContent,
    });

    console.log("Payment confirmation email sent to", email);
    return true;
  } catch (err) {
    console.error("Failed to send payment confirmation email:", err.message);
    return false;
  }
};
