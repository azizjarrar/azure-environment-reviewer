function renderOverview(summary) {
  const grid = document.getElementById('overview-grid');
  grid.innerHTML = '';

  const sectionMeta = {
    iam:            { label: 'IAM / RBAC',       sub: 'Role assignments & definitions' },
    networking:     { label: 'Networking',        sub: 'NSGs, VNets, IPs, firewalls' },
    storage:        { label: 'Storage',           sub: 'Accounts & containers' },
    compute:        { label: 'Compute',           sub: 'VMs, App Services, AKS' },
    securityCenter: { label: 'Security Center',   sub: 'Score, recommendations, alerts' },
    keyVault:       { label: 'Key Vault',         sub: 'Vaults, secrets, keys, certs' },
    monitor:        { label: 'Monitor',           sub: 'Alerts, workspaces, profiles' },
    resourceGroups: { label: 'Resource Groups',   sub: 'All RGs with full resource lists' },
    policy:         { label: 'Azure Policy',      sub: 'Assignments, custom definitions, initiatives' },
  };

  const total = document.createElement('div');
  total.className = 'overview-card';
  total.style.borderTopColor = '#0078D4';
  total.innerHTML = `
    <div class="overview-card-count">${summary.total}</div>
    <div class="overview-card-label">Total Resources</div>
    <div class="overview-card-sub">Across all sections</div>
  `;
  grid.appendChild(total);

  for (const [key, count] of Object.entries(summary.bySection)) {
    const meta = sectionMeta[key] || { label: key, sub: '' };
    const card = document.createElement('div');
    card.className = 'overview-card';
    card.style.cursor = 'pointer';
    card.innerHTML = `
      <div class="overview-card-count">${count}</div>
      <div class="overview-card-label">${escHtml(meta.label)}</div>
      <div class="overview-card-sub">${escHtml(meta.sub)}</div>
    `;
    card.addEventListener('click', () => activateTab(key));
    grid.appendChild(card);
  }

  document.getElementById('badge-overview').textContent = summary.total;
  document.getElementById('badge-overview').classList.remove('hidden');
  emptyState.classList.add('hidden');
}

function renderSection(sectionKey, resources) {
  if (sectionKey === 'resourceGroups') {
    renderResourceGroupsSection(resources);
    return;
  }

  const body = document.getElementById(`body-${sectionKey}`);
  if (!body) return;

  emptyState.classList.add('hidden');

  if (!resources.length) {
    body.innerHTML = `<p class="val-null" style="padding:20px 0">No resources found for this section.</p>`;
    return;
  }

  const byType = {};
  for (const r of resources) {
    const t = r.type || 'Resource';
    if (!byType[t]) byType[t] = [];
    byType[t].push(r);
  }

  body.innerHTML = '';
  for (const [typeName, items] of Object.entries(byType)) {
    const group = document.createElement('div');
    group.className = 'resource-group';

    const header = document.createElement('div');
    header.className = 'resource-group-header';
    header.innerHTML = `
      <span class="resource-type-label">${escHtml(typeToLabel(typeName))}</span>
      <span class="resource-type-count">${items.length}</span>
    `;
    group.appendChild(header);

    const tableWrap = document.createElement('div');
    tableWrap.className = 'table-wrap';
    tableWrap.innerHTML = buildTable(items);
    group.appendChild(tableWrap);
    body.appendChild(group);
  }
}

function renderResourceGroupsSection(resources) {
  const body = document.getElementById('body-resourceGroups');
  if (!body) return;

  emptyState.classList.add('hidden');

  if (!resources.length) {
    body.innerHTML = `<p class="val-null" style="padding:20px 0">No resource groups found.</p>`;
    return;
  }

  const group = document.createElement('div');
  group.className = 'resource-group';

  const header = document.createElement('div');
  header.className = 'resource-group-header';
  header.innerHTML = `
    <span class="resource-type-label">Resource Groups</span>
    <span class="resource-type-count">${resources.length}</span>
  `;
  group.appendChild(header);

  const tableWrap = document.createElement('div');
  tableWrap.className = 'table-wrap';

  const thead = `<tr>
    <th>Name</th><th>Location</th><th>Resource Count</th><th>Tags</th><th>Resources</th>
  </tr>`;

  const tbody = resources.map(rg => {
    const subKeys = [...new Set((rg.resources || []).flatMap(r => Object.keys(r)))];
    const subHead = `<tr>${subKeys.map(k => `<th>${escHtml(camelToLabel(k))}</th>`).join('')}</tr>`;
    const subBody = (rg.resources || []).map(r =>
      `<tr>${subKeys.map(k => `<td>${renderValue(k, r[k])}</td>`).join('')}</tr>`
    ).join('');
    const tableHtml = `<table class="resource-table"><thead>${subHead}</thead><tbody>${subBody}</tbody></table>`;
    const title = `${escHtml(rg.name)} — ${rg.resourceCount} resource${rg.resourceCount !== 1 ? 's' : ''}`;
    const mKey = `m${++modalIdCtr}`;
    modalStore[mKey] = { title, html: tableHtml };

    return `<tr class="rg-row" data-modal-key="${mKey}" style="cursor:pointer" title="Click to view resources">
      <td><strong>${escHtml(rg.name)}</strong></td>
      <td><span class="val-str">${escHtml(rg.location || '—')}</span></td>
      <td><span class="val-str">${rg.resourceCount}</span></td>
      <td><span class="val-str">${rg.tagCount}</span></td>
      <td>
        <button class="view-sub-btn" data-modal-key="${mKey}">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          ${rg.resourceCount} resource${rg.resourceCount !== 1 ? 's' : ''}
        </button>
      </td>
    </tr>`;
  }).join('');

  tableWrap.innerHTML = `<table class="resource-table"><thead>${thead}</thead><tbody>${tbody}</tbody></table>`;
  group.appendChild(tableWrap);
  body.appendChild(group);

  body.querySelectorAll('.rg-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('.view-sub-btn')) return;
      const entry = modalStore[row.dataset.modalKey];
      if (entry) openModal(entry.title, entry.html);
    });
  });
}

function buildTable(items) {
  const keySet = new Set();
  for (const item of items) {
    for (const k of Object.keys(item)) {
      if (k !== 'type') keySet.add(k);
    }
  }
  const keys = [...keySet];
  const thead = `<tr>${keys.map(k => `<th>${escHtml(camelToLabel(k))}</th>`).join('')}</tr>`;
  const tbody = items.map(item =>
    `<tr>${keys.map(k => `<td>${renderValue(k, item[k])}</td>`).join('')}</tr>`
  ).join('');
  return `<table class="resource-table"><thead>${thead}</thead><tbody>${tbody}</tbody></table>`;
}

function renderValue(key, val) {
  if (val === null || val === undefined) return '<span class="val-null">—</span>';

  if (typeof val === 'boolean') {
    return val ? '<span class="badge-true">Yes</span>' : '<span class="badge-false">No</span>';
  }

  if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(val)) {
    try { return `<span class="val-str">${escHtml(new Date(val).toLocaleString())}</span>`; }
    catch { /* fall through */ }
  }

  if (Array.isArray(val)) {
    if (!val.length) return '<span class="val-null">none</span>';

    if (typeof val[0] === 'object' && val[0] !== null) {
      const subKeys = [...new Set(val.flatMap(o => Object.keys(o)))];
      const subHead = `<tr>${subKeys.map(k => `<th>${escHtml(camelToLabel(k))}</th>`).join('')}</tr>`;
      const subBody = val.map(o =>
        `<tr>${subKeys.map(k => `<td>${renderValue(k, o[k])}</td>`).join('')}</tr>`
      ).join('');
      const tableHtml = `<table class="resource-table"><thead>${subHead}</thead><tbody>${subBody}</tbody></table>`;
      const mKey = `m${++modalIdCtr}`;
      modalStore[mKey] = { title: `${camelToLabel(key)} (${val.length})`, html: tableHtml };
      return `<button class="view-sub-btn" data-modal-key="${mKey}">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        ${val.length} ${val.length !== 1 ? 'items' : 'item'}
      </button>`;
    }

    return `<span class="val-arr">${val.map(v => escHtml(String(v))).join(', ')}</span>`;
  }

  if (typeof val === 'object') {
    const entries = Object.entries(val);
    if (!entries.length) return '<span class="val-null">—</span>';
    const tableHtml = `<table class="resource-table"><tbody>${entries.map(([k, v]) =>
      `<tr><th style="width:40%">${escHtml(camelToLabel(k))}</th><td>${renderValue(k, v)}</td></tr>`
    ).join('')}</tbody></table>`;
    const mKey = `m${++modalIdCtr}`;
    modalStore[mKey] = { title: `${camelToLabel(key)} — ${entries.length} field${entries.length !== 1 ? 's' : ''}`, html: tableHtml };
    return `<button class="view-sub-btn" data-modal-key="${mKey}">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
      ${entries.length} field${entries.length !== 1 ? 's' : ''}
    </button>`;
  }

  return `<span class="val-str">${escHtml(String(val))}</span>`;
}
