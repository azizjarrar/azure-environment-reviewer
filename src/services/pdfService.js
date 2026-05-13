'use strict';
const PDFDocument = require('pdfkit');
const fs          = require('fs');
const path        = require('path');
const { findLatestScanDir } = require('./reviewEngine');

// ── Design tokens ──────────────────────────────────────────────────────────────
const C = {
  azure:    '#0078D4', azureDk:  '#005a9e',
  white:    '#FFFFFF', text:     '#1a2332',
  muted:    '#637082', border:   '#d1dce8',
  light:    '#f3f6fb', codeBg:   '#1e2d3d',
  critical: '#C50F1F', high:     '#CA5010',
  medium:   '#835B00', low:      '#107C10',
};
const PW = 612, PH = 792;
const ML = 50,  MR = 50, MT = 55, MB = 55;
const CW = PW - ML - MR; // 512

// ── Utilities ──────────────────────────────────────────────────────────────────
function clean(s) {
  return (s || '')
    .replace(/🔴\s*/g,  '[CRITICAL] ').replace(/🟠\s*/g, '[HIGH] ')
    .replace(/🟡\s*/g,  '[MEDIUM] ')  .replace(/✅\s*/g, '[HEALTHY] ')
    .replace(/⚠️\s*/g, '[WARN] ')    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/[^\x00-\x7F]/g, '');
}

function sevColor(s) {
  const t = (s || '').toLowerCase();
  if (t.includes('critical') || t.includes('[critical]')) return C.critical;
  if (t.includes('high')     || t.includes('[high]'))     return C.high;
  if (t.includes('medium')   || t.includes('[medium]'))   return C.medium;
  if (t.includes('low')      || t.includes('[low]'))      return C.low;
  return null;
}

// ── Markdown → block array ────────────────────────────────────────────────────
function parseBlocks(md) {
  const lines = md.split('\n');
  const out   = [];
  let i = 0;

  while (i < lines.length) {
    const t = lines[i].trim();

    if (!t)                          { out.push({ type: 'space' }); i++; continue; }
    if (/^---+$/.test(t))            { out.push({ type: 'hr'    }); i++; continue; }
    if (t.startsWith('#### '))       { out.push({ type: 'h4', text: clean(t.slice(5)) }); i++; continue; }
    if (t.startsWith('### '))        { out.push({ type: 'h3', text: clean(t.slice(4)) }); i++; continue; }
    if (t.startsWith('## '))         { out.push({ type: 'h2', text: clean(t.slice(3)) }); i++; continue; }
    if (t.startsWith('# '))          { out.push({ type: 'h1', text: clean(t.slice(2)) }); i++; continue; }

    if (t.startsWith('|')) {
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        const l = lines[i].trim();
        if (!/^\|[\s\-|:]+\|$/.test(l))
          rows.push(l.replace(/^\||\|$/g, '').split('|').map(c => clean(c.trim())));
        i++;
      }
      if (rows.length) out.push({ type: 'table', rows });
      continue;
    }

    if (t.startsWith('```')) {
      const code = []; i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) { code.push(lines[i]); i++; }
      i++;
      out.push({ type: 'code', text: code.join('\n') });
      continue;
    }

    if (/^[-*]\s/.test(t) || /^\d+\.\s/.test(t)) {
      const items = [];
      while (i < lines.length &&
        (/^[-*]\s/.test(lines[i].trim()) || /^\d+\.\s/.test(lines[i].trim()))) {
        items.push(clean(lines[i].trim().replace(/^[-*]\s+|^\d+\.\s+/, '')));
        i++;
      }
      out.push({ type: 'list', items });
      continue;
    }

    out.push({ type: 'paragraph', text: clean(t) });
    i++;
  }
  return out;
}

// ── Table renderer ────────────────────────────────────────────────────────────
function drawTable(doc, rows, colWidths) {
  if (!rows || !rows.length) return;
  const PAD_X = 8, PAD_Y = 5, FS = 8.5, LH = 13;
  const totalW = colWidths.reduce((a, b) => a + b, 0);
  let y = doc.y;

  rows.forEach((row, ri) => {
    const isHead = ri === 0;

    // Measure row height
    let rowH = 24;
    row.forEach((cell, ci) => {
      if (ci >= colWidths.length) return;
      const avail = Math.max(colWidths[ci] - PAD_X * 2, 10);
      const lines = Math.ceil(((cell || '').length * 5.2) / avail) || 1;
      rowH = Math.max(rowH, lines * LH + PAD_Y * 2);
    });

    // Page break — sync doc.y so the new page header lands correctly
    if (y + rowH > PH - MB - 20) {
      doc.addPage();
      y = doc.y; // pdfkit sets doc.y = MT after addPage
    }

    // Row background
    const bg = isHead ? C.azure : (ri % 2 === 0 ? C.white : C.light);
    doc.rect(ML, y, totalW, rowH).fill(bg);

    // Outer rect border
    doc.rect(ML, y, totalW, rowH).strokeColor(C.border).lineWidth(0.5).stroke();

    // Cells
    let cx = ML;
    row.forEach((cell, ci) => {
      if (ci >= colWidths.length) return;
      const cellStr = String(cell || '');
      const sc      = isHead ? null : sevColor(cellStr);

      // Cell divider (right edge, except last)
      if (ci < colWidths.length - 1) {
        doc.moveTo(cx + colWidths[ci], y)
           .lineTo(cx + colWidths[ci], y + rowH)
           .strokeColor(C.border).lineWidth(0.5).stroke();
      }

      doc.font(isHead ? 'Helvetica-Bold' : 'Helvetica')
         .fontSize(FS)
         .fillColor(sc || (isHead ? C.white : C.text))
         .text(cellStr, cx + PAD_X, y + PAD_Y, {
           width: colWidths[ci] - PAD_X * 2,
           lineBreak: true, lineGap: 1,
         });

      cx += colWidths[ci];
    });

    y += rowH;
  });

  doc.y = Math.min(y + 10, PH - MB - 1);
}

// ── Smart column widths ────────────────────────────────────────────────────────
function autoWidths(rows, total) {
  if (!rows.length) return [];
  const cols   = rows[0].length;
  const maxLen = Array(cols).fill(0);
  rows.forEach(r => r.forEach((c, i) => { if (i < cols) maxLen[i] = Math.max(maxLen[i], (c || '').length); }));
  const sum = maxLen.reduce((a, b) => a + b, 0) || 1;
  return maxLen.map(l => Math.max(Math.floor(total * (l / sum)), 40));
}

// ── Page break guard ──────────────────────────────────────────────────────────
// Clamps doc.y to page bounds and adds a new page if less than `needed` pts remain.
function guard(doc, needed = 60) {
  if (doc.y > PH - MB) doc.y = PH - MB;
  if (doc.y + needed > PH - MB) doc.addPage();
}

// ── Section heading ────────────────────────────────────────────────────────────
// Forces a new page unless we are already at the very top of a fresh page.
function sectionHeading(doc, title) {
  if (doc.y > MT + 5) doc.addPage();
  const y = doc.y;
  const H = 36;
  doc.rect(0, y, PW, H).fill(C.light);
  doc.rect(ML, y, 4, H).fill(C.azure);
  doc.font('Helvetica-Bold').fontSize(13).fillColor(C.text)
     .text(title, ML + 14, y + 9, { width: CW - 14 });
  doc.y = y + H + 14;
}

// ── Block renderer ────────────────────────────────────────────────────────────
function renderBlocks(doc, blocks) {
  for (const b of blocks) {
    // Clamp doc.y — prevents silent drift past page boundary
    if (doc.y > PH - MB) doc.y = PH - MB;

    switch (b.type) {

      case 'space':
        // Only add space if we have room; never push past the page boundary
        if (doc.y + 10 < PH - MB) doc.moveDown(0.4);
        break;

      case 'hr':
        guard(doc, 20);
        doc.moveTo(ML, doc.y).lineTo(ML + CW, doc.y)
           .strokeColor(C.border).lineWidth(0.8).stroke();
        if (doc.y + 10 < PH - MB) doc.moveDown(0.5);
        break;

      case 'h1': {
        guard(doc, 50);
        const y = doc.y;
        doc.font('Helvetica-Bold').fontSize(17).fillColor(C.azure)
           .text(b.text, ML, y, { width: CW });
        doc.moveDown(0.15);
        doc.moveTo(ML, doc.y).lineTo(ML + CW, doc.y)
           .strokeColor(C.azure).lineWidth(1.5).stroke();
        doc.moveDown(0.5);
        break;
      }

      case 'h2': {
        if (doc.y > MT + 5) doc.addPage();
        const y = doc.y;
        doc.rect(ML, y, 4, 22).fill(C.azure);
        doc.font('Helvetica-Bold').fontSize(12).fillColor(C.text)
           .text(b.text, ML + 12, y + 3, { width: CW - 12 });
        doc.moveDown(0.4);
        doc.moveTo(ML, doc.y).lineTo(ML + CW, doc.y)
           .strokeColor(C.border).lineWidth(0.5).stroke();
        doc.moveDown(0.6);
        break;
      }

      case 'h3':
        guard(doc, 30);
        doc.font('Helvetica-Bold').fontSize(10.5).fillColor(C.text)
           .text(b.text, ML, doc.y, { width: CW });
        doc.moveDown(0.3);
        break;

      case 'h4':
        guard(doc, 24);
        doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted)
           .text(b.text, ML, doc.y, { width: CW });
        doc.moveDown(0.2);
        break;

      case 'paragraph':
        guard(doc, 24);
        doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
           .text(b.text, ML, doc.y, { width: CW, lineGap: 2 });
        doc.moveDown(0.4);
        break;

      case 'list':
        for (const item of b.items) {
          guard(doc, 20);
          const y = doc.y;
          doc.circle(ML + 4, y + 5, 2).fill(C.azure);
          doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
             .text(item, ML + 14, y, { width: CW - 14, lineGap: 2 });
          doc.moveDown(0.25);
        }
        doc.moveDown(0.3);
        break;

      case 'code': {
        const lines = b.text.trim().split('\n');
        const codeH = Math.max(lines.length * 13 + 20, 36);
        guard(doc, codeH);         // ensure space — THEN capture Y
        const codeY = doc.y;
        doc.rect(ML, codeY, CW, codeH).fill(C.codeBg);
        doc.font('Courier').fontSize(8).fillColor('#a8c8e8')
           .text(b.text.trim(), ML + 12, codeY + 10, { width: CW - 24, lineBreak: true, lineGap: 2 });
        doc.y = Math.max(doc.y, codeY + codeH) + 8;
        break;
      }

      case 'table': {
        guard(doc, 40);
        const widths = autoWidths(b.rows, CW);
        drawTable(doc, b.rows, widths);
        break;
      }
    }
  }
}

// ── Cover page ────────────────────────────────────────────────────────────────
function drawCover(doc, meta) {
  // Blue top panel
  doc.rect(0, 0, PW, 480).fill(C.azure);

  // Decorative circles (subtle)
  doc.save();
  doc.opacity(0.07);
  doc.circle(500, 80,  130).fill(C.white);
  doc.circle(80,  380, 100).fill(C.white);
  doc.circle(560, 320,  80).fill(C.white);
  doc.restore();

  // Logo block
  doc.rect(ML, 55, 44, 44).fill(C.white);
  doc.save();
  doc.polygon([ML + 22, 62], [ML + 8, 94], [ML + 36, 94]).fill(C.azure);
  doc.polygon([ML + 22, 72], [ML + 14, 88], [ML + 30, 88]).fill(C.white);
  doc.restore();
  doc.font('Helvetica-Bold').fontSize(11).fillColor(C.white).text('Azure', ML + 52, 66);
  doc.font('Helvetica').fontSize(11).fillColor(C.white).text('Review', ML + 52, 81);

  // Report title
  doc.font('Helvetica-Bold').fontSize(33).fillColor(C.white)
     .text('AZURE SECURITY', ML, 150, { width: CW, characterSpacing: 0.5 });
  doc.font('Helvetica-Bold').fontSize(33).fillColor(C.white)
     .text('ASSESSMENT REPORT', ML, 190, { width: CW, characterSpacing: 0.5 });

  // Accent line
  doc.rect(ML, 240, 90, 3).fill(C.white);

  // Subtitle
  doc.font('Helvetica').fontSize(12).fillColor('rgba(255,255,255,0.8)')
     .text('Enterprise Cloud Security Review', ML, 255, { width: CW });

  // Meta card
  const cardY = 305, cardH = 148;
  doc.rect(ML, cardY, CW, cardH).fill('rgba(0,0,0,0.22)');
  doc.rect(ML, cardY, 3, cardH).fill(C.white);

  const fields = [
    ['SUBSCRIPTION ID', meta.subscriptionId],
    ['SCAN DATE',       meta.scanDate],
    ['TOTAL RESOURCES', String(meta.totalResources)],
    ['PREPARED BY',     'Azure Review Platform — Azure Review Platform'],
    ['REPORT VERSION',  'v1.0  |  Classification: CONFIDENTIAL'],
  ];
  let fy = cardY + 14;
  fields.forEach(([label, value]) => {
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor('rgba(255,255,255,0.55)')
       .text(label, ML + 16, fy, { width: 140 });
    doc.font('Helvetica').fontSize(8.5).fillColor(C.white)
       .text(value || '—', ML + 165, fy, { width: CW - 180 });
    fy += 24;
  });

  // Dark bottom panel
  doc.rect(0, 480, PW, PH - 480).fill(C.azureDk);

  // Classification badge
  const badgeX = ML, badgeY = 510;
  doc.rect(badgeX, badgeY, 124, 30).fill('rgba(255,255,255,0.12)');
  doc.rect(badgeX, badgeY, 124, 30).strokeColor(C.white).lineWidth(0.8).stroke();
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.white)
     .text('CONFIDENTIAL', badgeX, badgeY + 9, { width: 124, align: 'center' });

  // Generated timestamp
  doc.font('Helvetica').fontSize(8).fillColor('rgba(255,255,255,0.45)')
     .text(`Report generated: ${meta.generatedAt}`, ML, PH - 44, { width: CW, align: 'right' });
}

// ── Per-page header ───────────────────────────────────────────────────────────
function drawHeader(doc) {
  doc.save();
  const oldY = doc.y;
  const m = doc.page.margins;
  doc.page.margins = { top: 0, bottom: 0, left: 0, right: 0 };

  doc.rect(0, 0, PW, 38).fill(C.azure);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(C.white)
     .text('AZURE SECURITY ASSESSMENT REPORT', ML, 13, { width: CW * 0.65 });
  doc.font('Helvetica').fontSize(8).fillColor('rgba(255,255,255,0.7)')
     .text('CONFIDENTIAL', 0, 13, { width: PW - MR, align: 'right' });
  
  doc.page.margins = m;
  doc.y = oldY;
  doc.restore();
}

// ── Per-page footer ───────────────────────────────────────────────────────────
function drawFooter(doc, subscriptionId, pageNum, total) {
  doc.save();
  const oldY = doc.y;
  const m = doc.page.margins;
  doc.page.margins = { top: 0, bottom: 0, left: 0, right: 0 };

  const y = PH - 36;
  doc.rect(0, y, PW, 36).fill(C.light);
  doc.moveTo(0, y).lineTo(PW, y).strokeColor(C.border).lineWidth(0.5).stroke();
  doc.font('Helvetica').fontSize(7.5).fillColor(C.muted)
     .text(`Sub: ${subscriptionId}`, ML, y + 12, { width: CW * 0.65 });
  doc.font('Helvetica').fontSize(7.5).fillColor(C.muted)
     .text(`Page ${pageNum} of ${total}  |  Azure Review Platform`, 0, y + 12, { width: PW - MR, align: 'right' });
  
  doc.page.margins = m;
  doc.y = oldY;
  doc.restore();
}

// ── Scope & Methodology ───────────────────────────────────────────────────────
function drawScopeMethodology(doc) {
  sectionHeading(doc, 'Scope & Methodology');

  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Assessment Scope', ML, doc.y);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
     .text(
       'This assessment covers all Azure resources discoverable via the Azure Resource Manager (ARM) API ' +
       'within the assessed subscription. The following security domains were reviewed:',
       ML, doc.y, { width: CW, lineGap: 2 }
     );
  doc.moveDown(0.5);

  const domains = [
    'IAM / RBAC — Role assignments, custom role definitions, privileged access',
    'Networking — NSGs, virtual networks, public IP addresses, load balancers',
    'Storage — Storage accounts, blob containers, access tiers and policies',
    'Compute — Virtual machines, container instances, App Services, AKS',
    'Key Vault — Vaults, access policies, key and secret configurations',
    'Security Center — Microsoft Defender for Cloud scores and recommendations',
    'Monitor & Logging — Diagnostic settings, Log Analytics workspaces, alerts',
    'Resource Groups — Governance, tagging compliance, resource inventory',
  ];
  domains.forEach(d => {
    const y = doc.y;
    doc.circle(ML + 4, y + 5, 2).fill(C.azure);
    doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
       .text(d, ML + 14, y, { width: CW - 14 });
    doc.moveDown(0.25);
  });

  doc.moveDown(0.8);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Methodology', ML, doc.y);
  doc.moveDown(0.5);
  drawTable(doc, [
    ['Phase',              'Activity',              'Detail'],
    ['1 — Discovery',      'Resource Enumeration',  'All resources listed via ARM API across every resource group'],
    ['2 — Configuration',  'Settings Collection',   'Security-relevant properties collected per resource type'],
    ['3 — IAM Review',     'RBAC Analysis',         'Role assignments and custom definitions cross-referenced'],
    ['4 — Network Audit',  'NSG & Exposure Check',  'Inbound rules, public IP exposure, and firewall policies reviewed'],
    ['5 — AI Analysis',    'Automated Correlation', 'Azure AI Foundry agent maps findings to CIS Benchmark v2'],
  ], [100, 130, CW - 230]);

  doc.moveDown(0.6);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Limitations', ML, doc.y);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
     .text(
       'This is a read-only, non-intrusive configuration assessment. No penetration testing, ' +
       'exploitation, or resource modification was performed. Findings reflect the configuration state ' +
       'at scan time only. Resources requiring permissions beyond the provided Service Principal scope may not be fully assessed.',
       ML, doc.y, { width: CW, lineGap: 2 }
     );
}

// ── Risk scoring matrix ───────────────────────────────────────────────────────
function drawRiskMatrix(doc) {
  sectionHeading(doc, 'Risk Scoring Matrix');

  doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
     .text(
       'Findings are classified using a combination of potential impact and likelihood of exploitation, ' +
       'aligned with CVSS v3.1 base score ranges and CIS Azure Benchmark severity definitions.',
       ML, doc.y, { width: CW, lineGap: 2 }
     );
  doc.moveDown(0.8);

  drawTable(doc, [
    ['Severity',     'CVSS',       'Criteria',                                                           'SLA'],
    ['[CRITICAL]',   '9.0 – 10.0', 'Publicly exploitable, direct data exposure or full compromise',     'Remediate within 24 h'],
    ['[HIGH]',       '7.0 – 8.9',  'Significant risk of unauthorised access or privilege escalation',   'Remediate within 7 days'],
    ['[MEDIUM]',     '4.0 – 6.9',  'Limited impact, requires additional conditions to exploit',         'Remediate within 30 days'],
    ['[LOW]',        '0.1 – 3.9',  'Minimal direct impact, hardening or best-practice recommendation',  'Remediate within 90 days'],
    ['[INFO]',       '0.0',        'Informational — no immediate risk identified',                      'At next review cycle'],
  ], [90, 80, CW - 250, 80]);

  doc.moveDown(0.8);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Compliance Frameworks Referenced', ML, doc.y);
  doc.moveDown(0.4);

  drawTable(doc, [
    ['Framework',                      'Version',  'Usage in this Report'],
    ['CIS Azure Foundations Benchmark', 'v2.0',    'Primary control mapping for all findings'],
    ['NIST SP 800-53',                  'Rev 5',   'Supplementary control cross-reference'],
    ['ISO/IEC 27001',                   '2022',    'Annex A control mapping for compliance observations'],
    ['Microsoft Cloud Security Benchmark','v1',    'Azure-native baseline for Defender for Cloud findings'],
  ], [170, 70, CW - 240]);
}

// ── Sign-off page ─────────────────────────────────────────────────────────────
function drawSignOff(doc) {
  sectionHeading(doc, 'Document Sign-Off & Distribution');

  doc.font('Helvetica').fontSize(9.5).fillColor(C.text)
     .text(
       'This report must be reviewed and formally acknowledged by the responsible parties before ' +
       'distribution beyond the named recipient. All copies are subject to the classification ' +
       'marking on the cover page.',
       ML, doc.y, { width: CW, lineGap: 2 }
     );
  doc.moveDown(0.8);

  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Sign-Off', ML, doc.y);
  doc.moveDown(0.4);

  drawTable(doc, [
    ['Role',                   'Name',  'Organisation',              'Signature', 'Date'],
    ['Prepared By',            '',      'Azure Review Platform',      '',          ''],
    ['Technical Reviewer',     '',      '',                           '',          ''],
    ['Approved By (CISO/CTO)', '',      '',                           '',          ''],
    ['Client Acknowledged',    '',      '',                           '',          ''],
  ], [120, 90, 120, 100, 82]);

  doc.moveDown(0.8);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text).text('Distribution List', ML, doc.y);
  doc.moveDown(0.4);

  drawTable(doc, [
    ['Name / Role',  'Organisation', 'Copy Type', 'Date Issued'],
    ['',             '',             'Electronic', ''],
    ['',             '',             'Electronic', ''],
  ], [160, 140, 100, 112]);

  doc.moveDown(1.2);

  // Disclaimer box
  const boxY = doc.y;
  const boxH = 68;
  doc.rect(ML, boxY, CW, boxH).fill(C.light);
  doc.rect(ML, boxY, CW, boxH).strokeColor(C.border).lineWidth(0.5).stroke();
  doc.rect(ML, boxY, 4, boxH).fill(C.azure);
  doc.font('Helvetica-Bold').fontSize(9).fillColor(C.text).text('DISCLAIMER', ML + 16, boxY + 10);
  doc.font('Helvetica').fontSize(8.5).fillColor(C.muted)
     .text(
       'This report contains confidential information intended solely for the named client organisation. ' +
       'The findings represent the security posture of the environment at the time of the assessment only and may ' +
       'not reflect subsequent changes. Azure Review Platform / Azure Review Platform accepts no liability for decisions ' +
       'made solely on the basis of this report without independent verification.',
       ML + 16, boxY + 26, { width: CW - 32, lineGap: 2 }
     );
}

// ── Main export ───────────────────────────────────────────────────────────────
async function generatePDF(subscriptionId, reviewId = null) {
  const Review = require('../models/Review');
  let markdown, summary;

  if (reviewId) {
    const reviewDoc = await Review.findOne({ reviewId, subscriptionId }).lean();
    if (!reviewDoc) throw new Error(`Review ${reviewId} not found.`);

    if (reviewDoc.reportContent) {
      markdown = reviewDoc.reportContent;
    } else {
      const reportPath = path.join(reviewDoc.scanDir, 'report.md');
      if (!fs.existsSync(reportPath))
        throw new Error('AI report not generated yet. Click "AI Report" first, then export.');
      markdown = fs.readFileSync(reportPath, 'utf8');
    }
    summary = reviewDoc.summary || {};
  } else {
    const scanDir = findLatestScanDir(subscriptionId);
    if (!scanDir) throw new Error('No scan data found. Run a review first.');
    const reportPath = path.join(scanDir, 'report.md');
    if (!fs.existsSync(reportPath))
      throw new Error('AI report not generated yet. Click "AI Report" first, then export.');
    markdown = fs.readFileSync(reportPath, 'utf8');
    const summaryPath = path.join(scanDir, 'summary.json');
    summary = fs.existsSync(summaryPath) ? JSON.parse(fs.readFileSync(summaryPath, 'utf8')) : {};
  }

  return _buildPDF(subscriptionId, markdown, summary);
}

function _buildPDF(subscriptionId, markdown, summary) {
  return new Promise((resolve, reject) => {

    const d = summary.generatedAt ? new Date(summary.generatedAt) : new Date();
    const meta = {
      subscriptionId: summary.subscriptionId || subscriptionId,
      scanDate:       d.toISOString().slice(0, 10),
      generatedAt:    d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }),
      totalResources: summary.bySection ? Object.values(summary.bySection).reduce((a, b) => a + b, 0) : 0,
    };

    const doc = new PDFDocument({
      autoFirstPage: false,
      bufferPages:   true,
      size:          [PW, PH],
      margins:       { top: MT, bottom: MB, left: ML, right: MR },
      info: {
        Title:    'Azure Security Assessment Report',
        Author:   'Azure Review Platform — Azure Review Platform',
        Subject:  `Security Assessment — ${meta.subscriptionId}`,
        Keywords: 'azure, security, assessment, cloud, confidential',
      },
    });

    const chunks = [];
    doc.on('data',  c => chunks.push(c));
    doc.on('end',   () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // ── 1. Cover (no margins — full bleed design)
    doc.addPage({ size: [PW, PH], margin: 0 });
    drawCover(doc, meta);

    // ── 2. Scope & Methodology (First content page)
    doc.addPage({ size: [PW, PH], margins: { top: MT, bottom: MB, left: ML, right: MR } });
    drawScopeMethodology(doc);

    // ── 3. Risk Scoring Matrix (Continues or adds page if needed)
    drawRiskMatrix(doc);

    // ── 4. AI Report content
    // We want the AI report to start on a new page
    if (doc.y > MT + 5) doc.addPage();
    renderBlocks(doc, parseBlocks(markdown));

    // ── 5. Sign-off
    // We want sign-off on a new page
    if (doc.y > MT + 5) doc.addPage();
    drawSignOff(doc);

    // ── Post-process: headers + footers on every non-cover page
    const range = doc.bufferedPageRange();
    const total  = range.count - 1; // content pages only
    for (let i = 0; i < range.count; i++) {
      if (i === 0) continue;
      doc.switchToPage(range.start + i);
      drawHeader(doc);
      drawFooter(doc, meta.subscriptionId, i, total);
    }

    doc.end();
  });
}

module.exports = { generatePDF };
