import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Optional but VERY helpful for debugging
transporter.verify((error, success) => {
    if (error) {
        console.error("SMTP connection error:", error);
    } else {
        console.log("SMTP server ready to send emails ✅");
    }
});

const sendEmail = async (to, subject, text) => {
    const info = await transporter.sendMail({
        from: `"Nova International" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        text
    });

    console.log("Email sent:", info.messageId);
};

export default sendEmail;
