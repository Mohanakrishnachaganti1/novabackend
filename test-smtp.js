import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

console.log("\n🔍 TESTING GMAIL SMTP CONNECTION\n");
console.log("═".repeat(50));
console.log("SMTP Configuration:");
console.log("  Host:", process.env.SMTP_HOST);
console.log("  Port:", process.env.SMTP_PORT);
console.log("  User:", process.env.SMTP_USER);
console.log("  Password length:", process.env.SMTP_PASS ? process.env.SMTP_PASS.length : "NOT SET");
console.log("═".repeat(50));

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT),
    secure: false, // TLS
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

console.log("\n⏳ Testing connection...\n");

transporter.verify((error, success) => {
    if (error) {
        console.log("❌ CONNECTION FAILED\n");
        console.log("Error:", error.message);
        console.log("\n🔧 TROUBLESHOOTING:");
        console.log("1. Is your Gmail App Password 16 characters? (Currently:", process.env.SMTP_PASS?.length, "chars)");
        console.log("2. Did you enable 2-Step Verification in Gmail?");
        console.log("3. Did you generate an App Password (not regular password)?");
        console.log("4. Check: https://myaccount.google.com/apppasswords");
        process.exit(1);
    } else {
        console.log("✅ CONNECTION SUCCESSFUL!\n");
        console.log("Sending test email to:", process.env.SMTP_USER);
        sendTestEmail();
    }
});

async function sendTestEmail() {
    try {
        const info = await transporter.sendMail({
            from: `"Nova Test" <${process.env.SMTP_USER}>`,
            to: process.env.SMTP_USER,
            subject: "✅ Nova International - SMTP Test",
            html: `
        <h2 style="color: #667eea;">✅ Email Configuration Working!</h2>
        <p>Your Gmail SMTP is configured correctly.</p>
        <p><strong>From:</strong> ${process.env.SMTP_USER}</p>
        <p><strong>Sent at:</strong> ${new Date().toLocaleString()}</p>
        <hr>
        <p style="color: #666; font-size: 12px;">If you see this email, purchase order confirmations will work perfectly!</p>
      `,
        });

        console.log("✅ TEST EMAIL SENT SUCCESSFULLY!\n");
        console.log("Message ID:", info.messageId);
        console.log("\n📧 Check your Gmail inbox at:", process.env.SMTP_USER);
        console.log("   (May take 1-2 minutes or check spam folder)");
        console.log("\n✨ Your email system is ready for purchase orders!\n");
    } catch (error) {
        console.log("❌ FAILED TO SEND EMAIL\n");
        console.log("Error:", error.message);
        process.exit(1);
    }
}
