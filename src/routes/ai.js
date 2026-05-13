const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const router   = express.Router();
const { requireSession } = require('../middleware/auth');
const { generateReport, chatWithAgent, isConfigured } = require('../services/aiService');
const { generatePDF }  = require('../services/pdfService');
const { generateDOCX } = require('../services/docxService');
const AzureCredential = require('../models/AzureCredential');
const Review          = require('../models/Review');

// GET /api/ai/status — returns whether AI features are configured (no auth required)
router.get('/status', (req, res) => {
  if (isConfigured()) {
    res.json({ available: true });
  } else {
    res.json({
      available: false,
      message: 'AI features require Azure AI Foundry. Set PROJECT_ENDPOINT and AGENT_NAME in your .env file.',
    });
  }
});

// GET /api/ai/report — Generates an AI report. Optional ?reviewId= for a specific review.
router.get('/report', requireSession, async (req, res) => {
  try {
    const subscriptionId = req.azureCreds.subscriptionId;
    const result = await generateReport(subscriptionId, req.query.reviewId || null, req.session.userId);
    res.json(result);
  } catch (error) {
    const status = error.message?.includes('No scan data') || error.message?.includes('not found') ? 400 : 500;
    res.status(status).json({ error: error.message || 'Failed to generate AI report.' });
  }
});

// GET /api/ai/pdf — Export as PDF. Optional ?reviewId= for a specific review.
router.get('/pdf', requireSession, async (req, res) => {
  try {
    const subscriptionId = req.azureCreds.subscriptionId;
    const buffer = await generatePDF(subscriptionId, req.query.reviewId || null);
    const filename = `azure-security-assessment-${subscriptionId.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type',        'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length',      buffer.length);
    res.end(buffer);
  } catch (error) {
    const status = error.message?.includes('not generated') ? 400 : 500;
    res.status(status).json({ error: error.message || 'Failed to generate PDF.' });
  }
});

// GET /api/ai/docx — Export AI report as .docx (Word / Google Docs). Optional ?reviewId=
router.get('/docx', requireSession, async (req, res) => {
  try {
    const subscriptionId = req.azureCreds.subscriptionId;
    const buffer = await generateDOCX(subscriptionId, req.query.reviewId || null);
    const filename = `azure-security-assessment-${subscriptionId.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.docx`;
    res.setHeader('Content-Type',        'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length',      buffer.length);
    res.end(buffer);
  } catch (error) {
    const status = error.message?.includes('not generated') || error.message?.includes('not found') ? 400 : 500;
    res.status(status).json({ error: error.message || 'Failed to generate Word document.' });
  }
});

// GET /api/ai/reports?reviewId=xxx — list AI reports for a review
router.get('/reports', requireSession, async (req, res) => {
  const { reviewId } = req.query;
  const subscriptionId = req.azureCreds.subscriptionId;
  if (!reviewId) return res.status(400).json({ error: 'reviewId required.' });

  try {
    const review = await Review.findOne({ reviewId, subscriptionId }).lean();
    if (!review) return res.status(404).json({ error: 'Review not found.' });

    const reports = [];

    if (review.reportContent) {
      // Primary: report stored in DB
      const date = review.reportGeneratedAt
        ? new Date(review.reportGeneratedAt).toISOString().slice(0, 10)
        : new Date(review.updatedAt).toISOString().slice(0, 10);
      reports.push({ filename: `${reviewId}-${date}.md`, date });
    } else {
      // Fallback: scan filesystem for old reports
      const subDir = path.join(__dirname, '../../output', subscriptionId);
      if (fs.existsSync(subDir)) {
        const files = fs.readdirSync(subDir)
          .filter(f => f.startsWith(`${reviewId}-`) && f.endsWith('.md'))
          .sort()
          .reverse();
        for (const file of files) {
          reports.push({ filename: file, date: file.slice(reviewId.length + 1, -3) });
        }
      }
    }

    res.json({ reports, reviewName: review.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ai/report-content?reviewId=xxx&filename=xxx — return markdown of a saved report
router.get('/report-content', requireSession, async (req, res) => {
  const { reviewId, filename } = req.query;
  const subscriptionId = req.azureCreds.subscriptionId;
  if (!reviewId) return res.status(400).json({ error: 'reviewId required.' });

  try {
    // Primary: read from DB
    const review = await Review.findOne({ reviewId, subscriptionId }).lean();
    if (review?.reportContent) {
      return res.json({ content: review.reportContent, filename: filename || `${reviewId}.md` });
    }

    // Fallback: read from file
    if (!filename) return res.status(404).json({ error: 'Report not found.' });
    if (!/^[a-f0-9]{8}-\d{4}-\d{2}-\d{2}\.md$/.test(filename))
      return res.status(400).json({ error: 'Invalid filename.' });

    const filePath = path.join(__dirname, '../../output', subscriptionId, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Report file not found.' });

    const content = fs.readFileSync(filePath, 'utf8');

    // Migrate to DB while serving
    Review.findOneAndUpdate({ reviewId }, { reportContent: content })
      .catch(e => console.error('[ai] migrate reportContent failed:', e.message));

    res.json({ content, filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/chat — Follow-up interactive chat
router.post('/chat', requireSession, async (req, res) => {
  const { conversationId, message } = req.body;
  
  if (!conversationId || !message) {
    return res.status(400).json({ error: 'conversationId and message are required.' });
  }

  try {
    const result = await chatWithAgent(conversationId, message, req.session.userId, req.body.reviewId || null);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to get AI response.' });
  }
});

module.exports = router;
