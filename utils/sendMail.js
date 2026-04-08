const nodemailer = require("nodemailer");

const sendMail = async (to, subject, text) => {
    try {
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS   // ✅ FIXED
            },
        });

        await transporter.verify();
        console.log("Mail server ready");

        await transporter.sendMail({
            from: `"Auth App" <${process.env.EMAIL_USER}>`, 
            to,
            subject,
            text
        });

        console.log("Email sent successfully");

    } catch (error) {
        console.error("Error sending email:", error.message);
        throw error;
    }
};

module.exports = sendMail;
