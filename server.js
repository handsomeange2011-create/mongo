// server.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// =====================
// CONFIG
// =====================
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const CREATOR_EMAIL = (process.env.CREATOR_EMAIL || "").toLowerCase();

// =====================
// DB SETUP
// =====================
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// =====================
// USER MODEL
// =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  isPremium: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

// =====================
// MIDDLEWARE
// =====================
function auth(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Invalid token" });
  }
}

async function premiumOnly(req, res, next) {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ msg: "User not found" });
  if (!user.isPremium) return res.status(403).json({ msg: "Premium required" });
  next();
}

// =====================
// AUTH ROUTES
// =====================
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ msg: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({
      email: email.toLowerCase(),
      password: hashed,
      role: email.toLowerCase() === CREATOR_EMAIL ? "admin" : "user",
      isPremium: email.toLowerCase() === CREATOR_EMAIL ? true : false,
    });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, role: user.role, isPremium: user.isPremium });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, role: user.role, isPremium: user.isPremium });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// =====================
// ADMIN ROUTES
// =====================
app.post("/api/admin/redeem", auth, async (req, res) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: "User not found" });

    if (code === "JJK1" && user.email === CREATOR_EMAIL) {
      user.isPremium = true;
      user.role = "admin";
      await user.save();
      return res.json({ msg: "Creator promo applied", isPremium: true });
    }

    return res.status(400).json({ msg: "Invalid code" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

app.post("/api/admin/grant-premium", auth, async (req, res) => {
  try {
    const { targetEmail } = req.body;
    const requester = await User.findById(req.user.id);
    if (!requester || requester.role !== "admin") {
      return res.status(403).json({ msg: "Admin only" });
    }

    const target = await User.findOne({ email: targetEmail.toLowerCase() });
    if (!target) return res.status(404).json({ msg: "Target not found" });

    target.isPremium = true;
    await target.save();
    res.json({ msg: "Premium granted", target: target.email });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// =====================
// PREMIUM TEST ROUTE
// =====================
app.get("/api/premium-only", auth, premiumOnly, (req, res) => {
  res.json({ msg: "You are premium!" });
});

// =====================
// START SERVER
// =====================
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
