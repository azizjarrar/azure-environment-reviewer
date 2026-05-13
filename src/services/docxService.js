'use strict';
const {
  Document, Packer, Paragraph, TextRun,
  HeadingLevel, Table, TableRow, TableCell,
  WidthType, AlignmentType, ShadingType, BorderStyle, LevelFormat,
} = require('docx');
const fs   = require('fs');
const path = require('path');
const { findLatestScanDir } = require('./reviewEngine');

// ── Inline markdown parser ─────────────────────────────────────────────────────
// Returns an array of TextRun objects from a markdown inline string.
function parseInline(raw) {
  const text = String(raw ?? '').replace(/[^\x00-\x7F]/g, ''); // strip emoji
  const runs = [];
  const re = /(\*\*.*?\*\*|\*.*?\*|`.*?`|[^*`]+)/gs;
  let m;
  while ((m = re.exec(text)) !== null) {
    const tok = m[0];
    if (!tok) continue;
    if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4)
      runs.push(new TextRun({ text: tok.slice(2, -2), bold: true }));
    else if (tok.startsWith('*') && tok.endsWith('*') && tok.length > 2)
      runs.push(new TextRun({ text: tok.slice(1, -1), italics: true }));
    else if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2)
      runs.push(new TextRun({ text: tok.slice(1, -1), font: 'Courier New', size: 18 }));
    else
      runs.push(new TextRun({ text: tok }));
  }
  return runs.length ? runs : [new TextRun({ text })];
}

// ── Markdown block parser ──────────────────────────────────────────────────────
function parseBlocks(md) {
  const lines = md.split('\n');
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Headings h1–h4
    const hm = line.match(/^(#{1,4})\s+(.*)/);
    if (hm) {
      blocks.push({ type: `h${hm[1].length}`, text: hm[2].trim() });
      i++; continue;
    }

    // Fenced code block
    if (line.startsWith('```')) {
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++;
      blocks.push({ type: 'code', text: codeLines.join('\n') });
      continue;
    }

    // Markdown table
    if (line.trim().startsWith('|')) {
      const tableLines = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        tableLines.push(lines[i]);
        i++;
      }
      const rows = tableLines
        .filter(l => !/^\s*\|[-| :]+\|\s*$/.test(l))
        .map(l => l.replace(/^\||\|$/g, '').split('|').map(c => c.trim()));
      if (rows.length) blocks.push({ type: 'table', rows });
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(line.trim())) {
      blocks.push({ type: 'hr' });
      i++; continue;
    }

    // Unordered list
    if (/^[-*]\s/.test(line)) {
      const items = [];
      while (i < lines.length && /^[-*]\s/.test(lines[i])) {
        items.push(lines[i].replace(/^[-*]\s+/, ''));
        i++;
      }
      blocks.push({ type: 'list', items });
      continue;
    }

    // Ordered list
    if (/^\d+\.\s/.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s+/, ''));
        i++;
      }
      blocks.push({ type: 'numlist', items });
      continue;
    }

    // Blank line
    if (line.trim() === '') {
      blocks.push({ type: 'space' });
      i++; continue;
    }

    // Paragraph
    blocks.push({ type: 'paragraph', text: line });
    i++;
  }

  return blocks;
}

// ── Blocks → docx elements ─────────────────────────────────────────────────────
const HEADING_LEVEL = {
  h1: HeadingLevel.HEADING_1,
  h2: HeadingLevel.HEADING_2,
  h3: HeadingLevel.HEADING_3,
  h4: HeadingLevel.HEADING_4,
};

function blocksToElements(blocks) {
  const els = [];

  for (const block of blocks) {
    // Headings
    if (HEADING_LEVEL[block.type]) {
      els.push(new Paragraph({ text: block.text, heading: HEADING_LEVEL[block.type] }));
      continue;
    }

    switch (block.type) {
      case 'paragraph':
        els.push(new Paragraph({ children: parseInline(block.text) }));
        break;

      case 'space':
        els.push(new Paragraph({ children: [new TextRun({ text: '' })] }));
        break;

      case 'hr':
        els.push(new Paragraph({
          children: [new TextRun({ text: '' })],
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'CCCCCC' } },
        }));
        break;

      case 'list':
        for (const item of block.items) {
          els.push(new Paragraph({
            children: parseInline(item),
            bullet: { level: 0 },
          }));
        }
        break;

      case 'numlist':
        for (const item of block.items) {
          els.push(new Paragraph({
            children: parseInline(item),
            numbering: { reference: 'default-num', level: 0 },
          }));
        }
        break;

      case 'code': {
        const codeLines = block.text.split('\n');
        for (const cl of codeLines) {
          els.push(new Paragraph({
            children: [new TextRun({ text: cl || ' ', font: 'Courier New', size: 18 })],
            shading:  { type: ShadingType.SOLID, color: 'F0F0F0', fill: 'F0F0F0' },
          }));
        }
        break;
      }

      case 'table': {
        const [headers, ...bodyRows] = block.rows;
        if (!headers?.length) break;

        const colWidth = Math.floor(9000 / headers.length);

        const headerRow = new TableRow({
          tableHeader: true,
          children: headers.map(cell => new TableCell({
            width:    { size: colWidth, type: WidthType.DXA },
            shading:  { type: ShadingType.SOLID, color: 'DCE9F7', fill: 'DCE9F7' },
            children: [new Paragraph({ children: [new TextRun({ text: cell, bold: true })] })],
          })),
        });

        const dataRows = bodyRows.map(row =>
          new TableRow({
            children: headers.map((_, ci) => new TableCell({
              width:    { size: colWidth, type: WidthType.DXA },
              children: [new Paragraph({ children: parseInline(row[ci] ?? '') })],
            })),
          })
        );

        els.push(new Table({
          width: { size: 9000, type: WidthType.DXA },
          rows:  [headerRow, ...dataRows],
        }));
        els.push(new Paragraph({ children: [new TextRun({ text: '' })] })); // post-table spacing
        break;
      }
    }
  }

  return els;
}

// ── Main export ────────────────────────────────────────────────────────────────
async function generateDOCX(subscriptionId, reviewId = null) {
  const Review = require('../models/Review');
  let markdown;

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
  } else {
    const scanDir = findLatestScanDir(subscriptionId);
    if (!scanDir) throw new Error('No scan data found. Run a review first.');
    const reportPath = path.join(scanDir, 'report.md');
    if (!fs.existsSync(reportPath))
      throw new Error('AI report not generated yet. Click "AI Report" first, then export.');
    markdown = fs.readFileSync(reportPath, 'utf8');
  }
  const blocks   = parseBlocks(markdown);
  const children = blocksToElements(blocks);

  const doc = new Document({
    title:       'Azure Security Assessment Report',
    creator:     'Azure Review Platform',
    description: `Security assessment for subscription ${subscriptionId}`,
    styles: {
      default: {
        heading1: { run: { color: '0078D4', bold: true, size: 32 } },
        heading2: { run: { color: '005A9E', bold: true, size: 26 } },
        heading3: { run: { color: '1A2332', bold: true, size: 22 } },
        heading4: { run: { color: '637082', bold: true, size: 20 } },
      },
    },
    numbering: {
      config: [{
        reference: 'default-num',
        levels: [{
          level:     0,
          format:    LevelFormat.DECIMAL,
          text:      '%1.',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      }],
    },
    sections: [{ children }],
  });

  return Packer.toBuffer(doc);
}

module.exports = { generateDOCX };
