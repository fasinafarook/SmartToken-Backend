const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendOTPEmail = require('../services/mailer');
const { generateOTP } = require('../services/otpService');


const otpMap = new Map();

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ msg: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = generateOTP();

    // Store OTP + user data temporarily in otpMap
    otpMap.set(email, {
      otp,
      userData: { name, email, password: hashedPassword },
      expires: Date.now() + 5 * 60000
    });

    await sendOTPEmail(email, otp);

    res.json({ msg: 'OTP sent to your email for verification.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });
    if (!user.isVerified) return res.status(400).json({ msg: 'Please verify your email first.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = otpMap.get(email);

    if (!record) return res.status(400).json({ msg: 'OTP not sent' });
    if (Date.now() > record.expires) return res.status(400).json({ msg: 'OTP expired' });
    if (record.otp !== otp) return res.status(400).json({ msg: 'Invalid OTP' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: 'User already exists' });

    const newUser = new User({
      ...record.userData,
      isVerified: true,
    });
    await newUser.save();

    otpMap.delete(email);

    res.json({ msg: 'Email verified and user registered successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
