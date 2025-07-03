const express = require('express');
const { register, login, verifyOtp } = require('../controllers/userController');

const router = express.Router();

router.post('/signup', register);
router.post('/login', login);
router.post('/verify-otp', verifyOtp);

module.exports = router;
