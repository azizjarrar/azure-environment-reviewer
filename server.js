require('dotenv').config();
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']); // bypass local DNS that blocks MongoDB SRV lookups
const express    = require('express');
const session    = require('express-session');
const { MongoStore } = require('connect-mongo');
const helmet     = require('helmet');
const mongoose   = require('mongoose');
const path       = require('path');

const authRoutes        = require('./src/routes/auth');
const reviewRoutes      = require('./src/routes/review');
const userRoutes        = require('./src/routes/users');
const credentialRoutes  = require('./src/routes/credentials');
const aiRoutes          = require('./src/routes/ai');

const app  = express();
const PORT = process.env.PORT || 3007;

// ─── MongoDB connection ───────────────────────────────────────────────────────
const seedDemoUser = require('./src/utils/seed');

mongoose.connect(process.env.MONGODB_URI, { family: 4 })
  .then(() => { console.log('MongoDB connected'); return seedDemoUser(); })
  .catch(err => { console.error('MongoDB connection error:', err); process.exit(1); });

// ─── Security headers ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
    },
  },
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'azure-review-dev-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl:   process.env.MONGODB_URI,
    dbName:     'azure-review',
    collectionName: 'sessions',
    ttl:        8 * 60 * 60, // seconds — matches cookie maxAge
    autoRemove: 'native',
  }),
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   8 * 60 * 60 * 1000, // 8 hours
  },
}));

// ─── Static assets ────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ─── API routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',        authRoutes);
app.use('/api/review',      reviewRoutes);
app.use('/api/users',       userRoutes);
app.use('/api/credentials', credentialRoutes);
app.use('/api/ai',          aiRoutes);

// ─── Page routes ──────────────────────────────────────────────────────────────

// Landing — redirect to /review if already logged in
app.get('/', (req, res) => {
  if (req.session?.userId) return res.redirect('/review');
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Login / Signup — redirect logged-in users away
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/review');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  if (req.session?.userId) return res.redirect('/review');
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Settings — requires login
app.get('/settings', (req, res) => {
  if (!req.session?.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});

// Review dashboard — requires login
app.get('/review', (req, res) => {
  if (!req.session?.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'review.html'));
});

// ─── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`Azure Review Tool running at http://localhost:${PORT}`);
});
