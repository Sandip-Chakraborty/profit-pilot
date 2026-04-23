// ═══════════════════════════════════════════════════════════
//  PROFIT PILOT — Backend Server
//  Node.js + Express + MongoDB Atlas
// ═══════════════════════════════════════════════════════════

const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ──────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname))); // serve HTML files

// ── MONGODB CONNECTION ──────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅  MongoDB Atlas connected successfully!'))
  .catch(err => {
    console.error('❌  MongoDB connection error:', err.message);
    process.exit(1);
  });

// ── USER SCHEMA ─────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    minlength: 6,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  mobile: {
    type: String,
    default: '',
    trim: true,
  },
  referralCode: {
    type: String,
    default: '',
    trim: true,
  },
  role: {
    type: String,
    enum: ['user', 'demo', 'admin'],
    default: 'user',
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  lastLogin: {
    type: Date,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model('User', userSchema);

// ── SEED DEMO ACCOUNT ───────────────────────────────────────
async function seedDemoUser() {
  try {
    const exists = await User.findOne({ userId: 'DEMO001' });
    if (!exists) {
      const hashed = await bcrypt.hash('demo1234', 10);
      await User.create({
        userId: 'DEMO001',
        name: 'Demo User',
        password: hashed,
        mobile: '',
        role: 'demo',
      });
      console.log('✅  Demo account created: DEMO001 / demo1234');
    }
  } catch (err) {
    console.error('Demo seed error:', err.message);
  }
}

mongoose.connection.once('open', seedDemoUser);

// ── JWT MIDDLEWARE ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ══════════════════════════════════════════════════════════════
//  API ROUTES
// ══════════════════════════════════════════════════════════════

// ── REGISTER ────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { userId, name, password, mobile, referralCode } = req.body;

    // Validation
    if (!userId || userId.trim().length < 6)
      return res.status(400).json({ success: false, message: 'User ID must be at least 6 characters.' });
    if (!name || !name.trim())
      return res.status(400).json({ success: false, message: 'Full name is required.' });
    if (!password || password.length < 6)
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
    if (mobile && !/^\d{10}$/.test(mobile.trim()))
      return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });

    // Check duplicate
    const exists = await User.findOne({ userId: userId.toUpperCase() });
    if (exists)
      return res.status(409).json({ success: false, message: 'This User ID already exists. Choose another.' });

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Save to MongoDB
    const newUser = await User.create({
      userId: userId.toUpperCase(),
      name: name.trim(),
      password: hashed,
      mobile: mobile?.trim() || '',
      referralCode: referralCode?.trim() || '',
    });

    console.log(`📝  New user registered: ${newUser.userId} (${newUser.name})`);

    res.status(201).json({
      success: true,
      message: `Account created successfully! Your User ID: ${newUser.userId}`,
      userId: newUser.userId,
    });

  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ── LOGIN ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (!userId || !password)
      return res.status(400).json({ success: false, message: 'User ID and Password are required.' });

    // Find user
    const user = await User.findOne({ userId: userId.toUpperCase() });
    if (!user)
      return res.status(401).json({ success: false, message: 'Invalid User ID or Password.' });

    if (!user.isActive)
      return res.status(403).json({ success: false, message: 'Your account is deactivated. Contact support.' });

    // Check password
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ success: false, message: 'Invalid User ID or Password.' });

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.userId, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`🔑  Login: ${user.userId} at ${new Date().toLocaleTimeString()}`);

    res.json({
      success: true,
      message: 'Login successful!',
      token,
      user: {
        userId: user.userId,
        name: user.name,
        mobile: user.mobile,
        role: user.role,
        lastLogin: user.lastLogin,
      },
    });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ── GET ALL USERS (admin view) ───────────────────────────────
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).json({ success: false, message: 'Admin access only.' });

    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json({ success: true, count: users.length, users });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET PROFILE ──────────────────────────────────────────────
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId }, '-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── VERIFY TOKEN ─────────────────────────────────────────────
app.get('/api/verify', authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ── HEALTH CHECK ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'running',
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    time: new Date().toISOString(),
  });
});

// ── SERVE FRONTEND FILES ─────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// ── START SERVER ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('🚀  Profit Pilot Server running!');
  console.log(`🌐  Open: http://localhost:${PORT}`);
  console.log(`📊  Dashboard: http://localhost:${PORT}/dashboard`);
  console.log('');
});
