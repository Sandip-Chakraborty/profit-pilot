const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ MongoDB Connect
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected!"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

// ✅ User Schema
const UserSchema = new mongoose.Schema({
  userid: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  mobileno: { type: String, default: "" },
  referralCode: { type: String, default: "" },
  balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

// ✅ Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Login karo pehle!" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ success: false, message: "Token invalid!" });
  }
};

// ✅ Test Route
app.get("/", (req, res) => {
  res.json({ message: "✅ Profit Pilot Backend is Running!" });
});

// ✅ REGISTER
app.post("/api/v1/selfRegister", async (req, res) => {
  try {
    console.log("Register body:", req.body);
    const body = req.body || {};
    const userid = body.userid;
    const username = body.username;
    const password = body.password;
    const mobileno = body.mobileno || "";
    const referralCode = body.referralCode || "";

    if (!userid || !password || !username) {
      return res.status(400).json({ success: false, message: "Saari fields bharo!" });
    }

    const existing = await User.findOne({ userid });
    if (existing) {
      return res.status(400).json({ success: false, message: "Ye User ID already exist karta hai!" });
    }

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ userid, username, password: hashed, mobileno, referralCode, balance: 0 });
    await user.save();

    const token = jwt.sign({ id: user._id, userid: user.userid }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ success: true, message: "Account successfully bana gaya!", token: token, jwtToken: token, userId: user.userid, userid: user.userid, username: user.username });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// ✅ LOGIN
app.post("/api/v1/login", async (req, res) => {
  try {
    console.log("Login body:", req.body);
    const body = req.body || {};
    const userid = body.userid;
    const password = body.password;

    if (!userid || !password) {
      return res.status(400).json({ success: false, message: "User ID aur password bharo!" });
    }

    const user = await User.findOne({ userid });
    if (!user) return res.status(400).json({ success: false, message: "User ID galat hai!" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Password galat hai!" });

    const token = jwt.sign({ id: user._id, userid: user.userid }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, message: "Login successful!", token: token, jwtToken: token, userId: user.userid, userid: user.userid, username: user.username, balance: user.balance });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// ✅ DEMO LOGIN
app.post("/api/v1/demoLogin", async (req, res) => {
  const token = jwt.sign({ id: "demo123", userid: "demo" }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ success: true, message: "Demo login successful!", jwtToken: token, userId: "demo", username: "Demo User", balance: 10000 });
});

// ✅ GET USER INFO
app.get("/api/v1/user", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ success: false, message: "User nahi mila!" });
    res.json({ success: true, ...user.toObject() });
  } catch {
    res.status(500).json({ success: false, message: "Server error!" });
  }
});

// ✅ BROKER INFO
app.get("/api/v1/broker", authMiddleware, (req, res) => {
  res.json({ success: true, brokerName: "Profit Pilot", logo: "./profit-pilot-logo.png" });
});
app.get("/api/v1/broker/che", authMiddleware, (req, res) => {
  res.json({ success: true });
});

// ✅ LOGOUT
app.post("/api/v1/logout", authMiddleware, (req, res) => {
  res.json({ success: true, message: "Logout successful!" });
});

// ✅ VALIDATE TOKEN
app.get("/api/v1/validate", authMiddleware, (req, res) => {
  res.json({ success: true, message: "Token valid hai!" });
});

// ✅ GET AUTH
app.get("/api/v1/getAuth", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    res.json({ success: true, user });
  } catch {
    res.status(500).json({ success: false });
  }
});

// ✅ OTHER ROUTES
app.all("/api/v1/watchlist", authMiddleware, (req, res) => res.json({ success: true, watchlist: [] }));
app.all("/api/v1/onlywatchlist", authMiddleware, (req, res) => res.json({ success: true, watchlist: [] }));
app.all("/api/v1/tradeposition", authMiddleware, (req, res) => res.json({ success: true, positions: [] }));
app.all("/api/v1/chart", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/execution", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/ledger", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/get", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/Get", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/chat", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/addsltgt", authMiddleware, (req, res) => res.json({ success: true }));
app.all("/api/v1/limitmodify", authMiddleware, (req, res) => res.json({ success: true }));
app.all("/api/v1/marginsetting", authMiddleware, (req, res) => res.json({ success: true, data: {} }));
app.all("/api/v1/forgot", (req, res) => res.json({ success: true, message: "OTP sent!" }));
app.all("/api/v1/requestOTP", (req, res) => res.json({ success: true, message: "OTP sent!" }));
app.all("/api/v1/change", authMiddleware, (req, res) => res.json({ success: true }));
app.all("/api/v1/SubNotification", authMiddleware, (req, res) => res.json({ success: true }));
app.all("/api/v1/GetBkgExposure", authMiddleware, (req, res) => res.json({ success: true, data: {} }));
app.all("/api/v1/getLedgerReq", authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all("/api/v1/getWithdrawalLimitInfo", authMiddleware, (req, res) => res.json({ success: true, data: {} }));
app.all("/api/v1/mytpipay", authMiddleware, (req, res) => res.json({ success: true, data: {} }));

// ✅ Catch all unknown routes
app.all("*", (req, res) => {
  console.log("Unknown route:", req.method, req.path);
  res.json({ success: true, data: [] });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
