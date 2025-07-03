require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendOTPEmail(to, otp) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: 'GYM OTP Verification',
    text: `Paachuoooo nammada gymminta otp ithaan ttooooo ....: ${otp}`,
  });
}

module.exports = sendOTPEmail;
