const express          = require('express');
const fs               = require('fs');
const path             = require('path');
const router           = express.Router();
const { requireSession } = require('../middleware/auth');
const { buildClients } = require('../utils/azureClient');
const { decrypt }      = require('../utils/encryption');
const AzureCredential  = require('../models/AzureCredential');
const Review           = require('../models/Review');
const ReviewSection    = require('../models/ReviewSection');
const {
  runReview,
  checkIAM,
  checkNetworking,
  checkStorage,
  checkCompute,
  checkSecurityCenter,
  checkKeyVault,
  checkMonitor,
  checkResourceGroups,
} = require('../services/reviewEngine');

// GET /api/review/status
// Returns the active credential info so the dashboard can display it.
router.get('/status', async (req, res) => {
  if (!req.session?.userId)
    return res.json({ connected: false });

  const cred = await AzureCredential.findOne({ userId: req.session.userId, isActive: true })
    .select('label subscriptionId tenantId');

  if (!cred)
    return res.json({ connected: false, message: 'No Azure credentials configured.' });

  res.json({ connected: true, label: cred.label, subscriptionId: cred.subscriptionId });
});

// GET /api/review/stream?sections=all
// SSE endpoint — streams real-time audit events.
router.get('/stream', requireSession, async (req, res) => {
  const creds    = req.azureCreds;
  const sections = req.query.sections === 'all' || !req.query.sections
    ? 'all'
    : req.query.sections.split(',');

  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send     = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  const keepAlive = setInterval(() => res.write(': ping\n\n'), 15000);
  const cleanup  = () => { clearInterval(keepAlive); res.end(); };

  req.on('close', () => clearInterval(keepAlive));

  try {
    const clients = buildClients(creds);

    let name = (req.query.name || 'Unnamed Review').trim();
    const clash = await Review.findOne({
      userId:         req.session.userId,
      subscriptionId: creds.subscriptionId,
      name,
    }).lean();
    if (clash) {
      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      const suffix = `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
      name = `${name} · ${suffix}`;
    }

    await runReview(clients, creds.subscriptionId, sections, (event) => send(event.type, event), {
      name,
      userId: req.session.userId,
    });
  } catch (err) {
    send('error', { message: err.message });
  } finally {
    cleanup();
  }
});

// POST /api/review/section/:name — run a single section synchronously
router.post('/section/:name', requireSession, async (req, res) => {
  const creds   = req.azureCreds;
  const clients = buildClients(creds);
  const { subscriptionId } = creds;

  const sectionMap = {
    iam:            () => checkIAM(clients, subscriptionId),
    networking:     () => checkNetworking(clients),
    storage:        () => checkStorage(clients),
    compute:        () => checkCompute(clients),
    securityCenter: () => checkSecurityCenter(clients, subscriptionId),
    keyVault:       () => checkKeyVault(clients),
    monitor:        () => checkMonitor(clients, subscriptionId),
    resourceGroups: () => checkResourceGroups(clients),
  };

  const fn = sectionMap[req.params.name];
  if (!fn)
    return res.status(400).json({ error: `Unknown section. Valid: ${Object.keys(sectionMap).join(', ')}` });

  try {
    const resources = await fn();
    res.json({ section: req.params.name, resources });
  } catch (err) {
    console.error(`[review/section/${req.params.name}]`, err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/review/list — all reviews for the session user's active subscription
router.get('/list', async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'Please sign in.' });

  try {
    const cred = await AzureCredential.findOne({ userId: req.session.userId, isActive: true })
      .select('subscriptionId');
    if (!cred) return res.json({ reviews: [] });

    const reviews = await Review.find({ userId: req.session.userId, subscriptionId: cred.subscriptionId })
      .sort({ createdAt: -1 })
      .select('-findings -errors')
      .limit(50)
      .lean();

    res.json({ reviews });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/review/:reviewId/sections — load section JSON files from a past review
router.get('/:reviewId/sections', async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'Please sign in.' });

  try {
    const review = await Review.findOne({ reviewId: req.params.reviewId, userId: req.session.userId }).lean();
    if (!review) return res.status(404).json({ error: 'Review not found.' });

    const sectionKeys = ['iam', 'networking', 'storage', 'compute', 'securityCenter', 'keyVault', 'monitor', 'resourceGroups', 'policy'];
    let sections = {};

    const sectionDocs = await ReviewSection.find({ reviewId: review.reviewId }).lean();

    if (sectionDocs.length > 0) {
      // Primary path — data stored in ReviewSection collection
      for (const doc of sectionDocs) {
        sections[doc.key] = doc.data;
      }
    } else {
      // Fallback for old reviews — read from files and immediately migrate to DB
      for (const key of sectionKeys) {
        const filePath = path.join(review.scanDir, `${key}.json`);
        try {
          sections[key] = fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf8')) : [];
        } catch { sections[key] = []; }
      }

      // Migrate to ReviewSection so next load comes from DB, not files
      const toSave = Object.entries(sections).filter(([, data]) => data.length > 0);
      if (toSave.length > 0) {
        ReviewSection.bulkWrite(
          toSave.map(([key, data]) => ({
            updateOne: {
              filter: { reviewId: review.reviewId, key },
              update: { $set: { data } },
              upsert: true,
            },
          }))
        ).catch(e => console.error('[review] migrate to DB failed:', e.message));
      }
    }

    // Load findings from DB, fall back to file for old reviews
    let findings = review.findings || [];
    if (!findings.length) {
      const fp = path.join(review.scanDir, 'findings.json');
      try { findings = fs.existsSync(fp) ? JSON.parse(fs.readFileSync(fp, 'utf8')).findings || [] : []; } catch { /* */ }
    }

    res.json({ sections, summary: review.summary, findings, name: review.name, createdAt: review.createdAt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
