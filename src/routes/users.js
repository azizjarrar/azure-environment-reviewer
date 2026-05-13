const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const User     = require('../models/User');
const AIUsage  = require('../models/AIUsage');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// POST /api/users/signup
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || name.trim().length < 2)
    return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  if (!EMAIL_RE.test(email))
    return res.status(400).json({ error: 'Invalid email address.' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing)
      return res.status(409).json({ error: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, name, passwordHash });

    req.session.userId = user._id.toString();
    res.status(201).json({ ok: true, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('[signup]', err);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

// POST /api/users/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!EMAIL_RE.test(email))
    return res.status(400).json({ error: 'Invalid email address.' });
  if (!password)
    return res.status(400).json({ error: 'Password is required.' });

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user)
    return res.status(401).json({ error: 'Invalid email or password.' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid)
    return res.status(401).json({ error: 'Invalid email or password.' });

  req.session.userId = user._id.toString();
  res.json({ ok: true, user: { id: user._id, name: user.name, email: user.email } });
});

// POST /api/users/logout
router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// GET /api/users/me
router.get('/me', async (req, res) => {
  if (!req.session?.userId)
    return res.status(401).json({ error: 'Not authenticated.' });

  const user = await User.findById(req.session.userId).select('-passwordHash');
  if (!user)
    return res.status(401).json({ error: 'User not found.' });

  res.json({ user });
});

// GET /api/users/usage — AI token consumption summary for the logged-in user
router.get('/usage', async (req, res) => {
  if (!req.session?.userId)
    return res.status(401).json({ error: 'Not authenticated.' });

  try {
    const records = await AIUsage.find({ userId: req.session.userId })
      .sort({ createdAt: -1 })
      .lean();

    const totalInputTokens  = records.reduce((s, r) => s + r.inputTokens,  0);
    const totalOutputTokens = records.reduce((s, r) => s + r.outputTokens, 0);
    const totalCostUSD      = records.reduce((s, r) => s + r.costUSD,      0);
    const reportCount       = records.filter(r => r.type === 'report').length;
    const chatCount         = records.filter(r => r.type === 'chat').length;

    res.json({ totalInputTokens, totalOutputTokens, totalCostUSD, reportCount, chatCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
