function parseMarkdownTables(text) {
  const lines = text.split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    if (lines[i].trim().startsWith('|')) {
      const tableLines = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        tableLines.push(lines[i]);
        i++;
      }
      const rows = tableLines.filter(l => !/^\s*\|[-| :]+\|\s*$/.test(l));
      const parseRow = l => l.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
      const [head, ...body] = rows;
      const ths = parseRow(head).map(c => `<th>${c}</th>`).join('');
      const trs = body.map(r => `<tr>${parseRow(r).map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
      out.push(`<div class="table-wrap"><table class="resource-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table></div>`);
    } else {
      out.push(lines[i]);
      i++;
    }
  }
  return out.join('\n');
}

function formatMarkdown(markdown) {
  const withTables = parseMarkdownTables(markdown);
  return withTables
    .replace(/^# (.*$)/gim,   '<h1 style="color:var(--text);margin-top:24px">$1</h1>')
    .replace(/^## (.*$)/gim,  '<h2 style="color:var(--text);margin-top:20px;border-bottom:1px solid var(--border);padding-bottom:8px">$1</h2>')
    .replace(/^### (.*$)/gim, '<h3 style="color:var(--text);margin-top:16px">$1</h3>')
    .replace(/^\* (.*$)/gim,  '<li style="margin-left:20px;margin-bottom:8px">$1</li>')
    .replace(/^- (.*$)/gim,   '<li style="margin-left:20px;margin-bottom:8px">$1</li>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/```([\s\S]*?)```/gim, '<pre style="background:#1a2332;color:#fff;padding:15px;border-radius:8px;overflow-x:auto;margin:15px 0"><code>$1</code></pre>')
    .replace(/\n\n/gim, '<br><br>')
    .split('\n').map(line => line.trim().startsWith('<') ? line : `<p>${line}</p>`).join('');
}

async function loadAIReportList() {
  const bodyAi = document.getElementById('body-ai');

  if (!selectedReviewId) {
    bodyAi.innerHTML = `
      <div class="empty-state">
        <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#c8d6e5" stroke-width="1.2" style="opacity:0.4">
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
        </svg>
        <h3>No review selected</h3>
        <p>Select a review from the sidebar dropdown to see its generated reports.</p>
      </div>`;
    return;
  }

  bodyAi.innerHTML = `<div style="padding:24px;color:var(--muted);font-size:13px">Loading reports…</div>`;

  try {
    const res = await fetch(`/api/ai/reports?reviewId=${encodeURIComponent(selectedReviewId)}`);
    if (!res.ok) throw new Error((await res.json()).error || 'Failed to load reports.');
    const { reports, reviewName } = await res.json();

    if (!reports.length) {
      bodyAi.innerHTML = `
        <div class="empty-state">
          <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#8e44ad" stroke-width="1.2" style="opacity:0.25">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
          </svg>
          <h3>No reports yet</h3>
          <p>Click <strong>AI Report</strong> in the top bar to generate a report for this review.</p>
        </div>`;
      return;
    }

    const cards = reports.map(r => `
      <div style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid var(--border);border-radius:10px;margin-bottom:10px;background:var(--surface)">
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;font-size:14px;color:var(--text)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#8e44ad" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            ${escHtml(r.date)}
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:3px">${escHtml(r.filename)}</div>
        </div>
        <button class="btn-secondary view-report-btn" data-filename="${escHtml(r.filename)}"
          style="font-size:12px;padding:6px 14px;height:auto;white-space:nowrap">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:4px"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          View
        </button>
        <a class="btn-secondary" href="/api/ai/pdf?reviewId=${encodeURIComponent(selectedReviewId)}"
          style="font-size:12px;padding:6px 14px;height:auto;white-space:nowrap;text-decoration:none;border-color:#d13438;color:#d13438">PDF</a>
        <a class="btn-secondary" href="/api/ai/docx?reviewId=${encodeURIComponent(selectedReviewId)}"
          style="font-size:12px;padding:6px 14px;height:auto;white-space:nowrap;text-decoration:none;border-color:#185ABD;color:#185ABD">Word</a>
      </div>`).join('');

    bodyAi.innerHTML = `
      <div style="padding:20px 24px">
        <div style="font-size:13px;color:var(--muted);margin-bottom:16px">
          <strong style="color:var(--text)">${escHtml(reviewName)}</strong>
          &nbsp;·&nbsp; ${reports.length} report${reports.length !== 1 ? 's' : ''} generated
        </div>
        ${cards}
      </div>`;

    bodyAi.querySelectorAll('.view-report-btn').forEach(btn => {
      btn.addEventListener('click', () => loadAIReportContent(btn.dataset.filename));
    });
  } catch (err) {
    bodyAi.innerHTML = `<div class="error-state" style="margin:20px">${escHtml(err.message)}</div>`;
  }
}

async function loadAIReportContent(filename) {
  const bodyAi = document.getElementById('body-ai');
  bodyAi.innerHTML = `<div style="padding:24px;color:var(--muted);font-size:13px">Loading report…</div>`;
  try {
    const url = `/api/ai/report-content?reviewId=${encodeURIComponent(selectedReviewId)}&filename=${encodeURIComponent(filename)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error((await res.json()).error || 'Failed to load report.');
    const { content } = await res.json();
    renderAIReport(content, true);
  } catch (err) {
    bodyAi.innerHTML = `<div class="error-state" style="margin:20px">${escHtml(err.message)}</div>`;
  }
}

function renderAIReport(markdown, showBackBtn = false) {
  const bodyAi = document.getElementById('body-ai');
  const html = formatMarkdown(markdown);

  bodyAi.innerHTML = `
    <div class="ai-report-container" style="max-width:800px;margin:0 auto;line-height:1.6;padding:20px;color:var(--text)">
      ${showBackBtn ? `
      <button id="back-to-list-btn" style="display:inline-flex;align-items:center;gap:6px;background:none;border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12px;color:var(--muted);cursor:pointer;margin-bottom:16px">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"/></svg>
        Back to reports list
      </button>` : ''}
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px" class="no-print">
        <div style="background:#f8f9fa;border-left:4px solid #8e44ad;padding:10px 15px;font-size:13px;color:var(--muted)">
          <strong>AI Insights</strong> · Generated via Azure AI Foundry
        </div>
        <div style="display:flex;gap:10px">
          <button id="dl-md-btn" class="btn-secondary" style="font-size:11px;padding:5px 10px;height:auto">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px;vertical-align:-1px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Markdown
          </button>
          <button id="dl-pdf-btn" class="btn-secondary" style="font-size:11px;padding:5px 10px;height:auto;border-color:#d13438;color:#d13438">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px;vertical-align:-1px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            PDF Report
          </button>
          <button id="dl-docx-btn" class="btn-secondary" style="font-size:11px;padding:5px 10px;height:auto;border-color:#185ABD;color:#185ABD">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px;vertical-align:-1px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            Word / Docs
          </button>
        </div>
      </div>
      <div id="printable-ai-report">
        <div class="print-only" style="display:none;margin-bottom:30px;border-bottom:2px solid #8e44ad;padding-bottom:10px">
          <h1 style="margin:0">Azure Security AI Analysis</h1>
          <p style="color:#666">Generated on ${new Date().toLocaleString()} for Subscription ${document.getElementById('sub-badge').textContent}</p>
        </div>
        <div id="ai-report-content">${html}</div>
      </div>
      <div class="chat-section no-print" style="margin-top:40px;padding-top:20px;border-top:2px solid var(--border)">
        <h3 style="color:#8e44ad;margin-bottom:15px">Ask follow-up questions</h3>
        <div id="chat-history" style="margin-bottom:15px"></div>
        <div class="chat-input-wrap" style="display:flex;gap:10px">
          <input type="text" id="chat-input" placeholder="Ask about these findings..." style="flex:1;padding:10px;border-radius:var(--radius);border:1px solid var(--border)">
          <button id="chat-send-btn" class="btn-primary" style="background:#8e44ad;border:none">Send</button>
        </div>
      </div>
    </div>
  `;

  document.getElementById('dl-md-btn').addEventListener('click', () => {
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'Azure-AI-Report.md'; a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById('dl-pdf-btn').addEventListener('click', () => {
    window.location.href = `/api/ai/pdf?reviewId=${encodeURIComponent(selectedReviewId)}`;
  });

  document.getElementById('dl-docx-btn').addEventListener('click', () => {
    window.location.href = `/api/ai/docx?reviewId=${encodeURIComponent(selectedReviewId)}`;
  });

  const chatInput   = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send-btn');
  const chatHistory = document.getElementById('chat-history');

  async function sendChatMessage() {
    const msg = chatInput.value.trim();
    if (!msg) return;
    chatInput.value = '';
    chatInput.disabled = true;
    chatSendBtn.disabled = true;

    const userEl = document.createElement('div');
    userEl.style.margin = '10px 0';
    userEl.innerHTML = `<strong>You:</strong> ${escHtml(msg)}`;
    chatHistory.appendChild(userEl);

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conversationId: currentConversationId, message: msg }),
      });
      const data = await res.json();
      const agentEl = document.createElement('div');
      agentEl.style.cssText = 'margin:15px 0;padding:15px;background:#f3f6fb;border-radius:var(--radius)';
      agentEl.innerHTML = `<strong>Agent:</strong><div style="margin-top:5px">${formatMarkdown(data.reply)}</div>`;
      chatHistory.appendChild(agentEl);
    } catch (err) {
      console.error(err);
    } finally {
      chatInput.disabled = false;
      chatSendBtn.disabled = false;
      chatInput.focus();
    }
  }

  chatSendBtn.addEventListener('click', sendChatMessage);
  chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendChatMessage(); });

  if (showBackBtn) {
    document.getElementById('back-to-list-btn')?.addEventListener('click', loadAIReportList);
  }
}

aiBtn.addEventListener('click', async () => {
  if (!selectedReviewId) {
    showError('Please select a review from the sidebar first to generate an AI report.');
    return;
  }
  hideError();

  const bodyAi = document.getElementById('body-ai');
  aiBtn.disabled = true;
  aiBtn.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="spin" style="margin-right:6px;vertical-align:-2px">
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
    </svg>Analyzing…`;

  activateTab('ai');
  bodyAi.innerHTML = `
    <div style="padding:40px;text-align:center;color:var(--muted)">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#8e44ad" stroke-width="2" class="spin" style="margin-bottom:15px">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
      </svg>
      <p>Consulting Azure AI Foundry agents…</p>
      <p style="font-size:12px;opacity:0.7">This may take a few moments as specialized agents analyze each domain.</p>
    </div>`;

  try {
    const res = await fetch(`/api/ai/report?reviewId=${encodeURIComponent(selectedReviewId)}`);
    const data = await res.json();
    if (res.ok) {
      currentConversationId = data.conversationId;
      renderAIReport(data.report, true);
      document.getElementById('badge-ai').classList.add('hidden');
    } else {
      throw new Error(data.error || 'Failed to generate AI report');
    }
  } catch (err) {
    bodyAi.innerHTML = `<div class="error-state" style="margin:20px">${escHtml(err.message)}</div>`;
  } finally {
    aiBtn.disabled = false;
    aiBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="7.5 4.21 12 6.81 16.5 4.21"/><polyline points="7.5 19.79 7.5 14.63 3 12"/><polyline points="21 12 16.5 14.63 16.5 19.79"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
      AI Report`;
  }
});
