const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

router.post("/register", async (req, res) => {
  try {
    const { userId, accountName, password, mobile, referralCode } = req.body;
    const existingUser = await User.findOne({ userId });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Ye User ID already exist karta hai!" });
    }
    const existingMobile = await User.findOne({ mobile });
    if (existingMobile) {
      return res.status(400).json({ success: false, message: "Ye mobile number already registered hai!" });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ userId, accountName, password: hashedPassword, mobile, referralCode: referralCode || "", balance: 0, createdAt: new Date() });
    await newUser.save();
    const token = jwt.sign({ id: newUser._id, userId: newUser.userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ success: true, message: "Account successfully bana gaya!", token, user: { userId: newUser.userId, accountName: newUser.accountName, mobile: newUser.mobile, balance: newUser.balance } });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ success: false, message: "Server error aaya, dobara try karo!" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { userId, password } = req.body;
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(400).json({ success: false, message: "User ID galat hai ya exist nahi karta!" });
    }
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ success: false, message: "Password galat hai!" });
    }
    const token = jwt.sign({ id: user._id, userId: user.userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, message: "Login successful!", token, user: { userId: user.userId, accountName: user.accountName, mobile: user.mobile, balance: user.balance } });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: "Server error aaya, dobara try karo!" });
  }
});

module.exports = router;
