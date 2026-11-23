const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function apiBase() {
  return window.RI_CONFIG?.apiBase?.replace(/\/$/, '') || '';
}

function request(path, options = {}) {
  if (!apiBase()) return Promise.reject(Object.assign(new Error('Worker not configured'), { kind: 'config' }));
  return fetch(`${apiBase()}${path}`, { ...options, headers: { accept: 'application/json', ...(options.headers || {}) } }).then(async (response) => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error(data.error || `HTTP ${response.status}`), { status: response.status });
    return data;
  });
}

function csvRows(rows) {
  const headers = [...new Set(rows.flatMap((row) => Object.keys(row)))];
  const line = (values) => values.map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`).join(',');
  return [line(headers), ...rows.map((row) => line(headers.map((header) => row[header])))].join('\n');
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

let active = null;
let investigationHistory = [];
let activeResultTab = 'overview';

function setTab(name) {
  activeResultTab = name;
  window.history.replaceState(null, '', `#/osint/${name}`);
  document.querySelectorAll('[data-osint-tab]').forEach((tab) => {
    const selected = tab.dataset.osintTab === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  ['overview', 'new', 'email', 'username', 'breaches', 'exposure', 'relationships', 'timeline', 'history', 'reports'].forEach((panelName) => {
    const panel = panelName === 'new'
      ? $('#osint-new-panel')
      : panelName === 'overview'
        ? $('#osint-overview')
        : panelName === 'relationships'
          ? $('#osint-graph-panel')
          : panelName === 'timeline' || panelName === 'history' || panelName === 'reports' || panelName === 'email' || panelName === 'username' || panelName === 'breaches' || panelName === 'exposure'
              ? $('#osint-results')
              : null;
    if (panel) panel.hidden = panelName !== name;
  });
  if (['email', 'username', 'breaches', 'exposure', 'timeline', 'history', 'reports'].includes(name)) {
    $('#osint-results').hidden = false;
    renderResults(name);
  }
  if (name === 'relationships') renderGraph();
  if (name === 'history') renderHistory();
  if (name === 'reports') renderReports();
}

function renderSummary() {
  if (!active) {
    $('#osint-summary').innerHTML = '<article class="metric-card"><span>Status</span><strong>Idle</strong></article>';
    $('#osint-investigation-id').textContent = 'No active investigation';
    $('#osint-provider-status').innerHTML = '';
    $('#osint-context').innerHTML = '<p class="empty-copy">Start an investigation to add identifiers, provider results, evidence, and relationship context.</p>';
    $('#osint-assessment').innerHTML = '';
    return;
  }
  const summary = active.summary || {};
  const items = [
    ['Status', active.status],
    ['Providers', summary.total_providers || 0],
    ['Successful', summary.successful_providers || 0],
    ['Failed', summary.failed_providers || 0],
    ['Findings', summary.total_findings || 0],
  ];
  $('#osint-summary').innerHTML = items.map(([label, value]) => `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('');
  $('#osint-investigation-id').textContent = active.id;
  $('#osint-provider-status').innerHTML = (active.provider_jobs || []).map((job) => `<article class="status-card"><span class="status-name">${escapeHtml(job.provider)}</span><span class="status-copy"><span class="status-result ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span>${job.error ? `<small class="source-error">${escapeHtml(job.error)}</small>` : ''}</span></article>`).join('') || '<p class="empty-copy">No providers requested.</p>';
  const identifiers = active.identifiers || [];
  const emailCount = identifiers.filter((identifier) => identifier.type === 'email').length;
  const usernameCount = identifiers.filter((identifier) => identifier.type === 'username').length;
  const confirmedFindings = (active.results || []).filter((finding) => finding.status === 'FOUND').length;
  $('#osint-context').innerHTML = `<dl class="investigation-context">
    <div><dt>Search identifiers</dt><dd>${identifiers.length}</dd></div>
    <div><dt>Email addresses</dt><dd>${emailCount}</dd></div>
    <div><dt>Usernames</dt><dd>${usernameCount}</dd></div>
    <div><dt>Confirmed / found records</dt><dd>${confirmedFindings}</dd></div>
    <div><dt>Investigation mode</dt><dd>${escapeHtml(active.mode || 'standard')}</dd></div>
    <div><dt>Last updated</dt><dd>${escapeHtml(active.updated_at || 'Not available')}</dd></div>
  </dl>
  <div class="identifier-list"><span>Identifiers</span><div>${identifiers.length ? identifiers.map((identifier) => `<code>${escapeHtml(identifier.value)}</code>`).join('') : '<span class="empty-copy">None supplied</span>'}</div></div>`;
  const accounts = (active.results || []).filter((finding) => finding.type === 'social_account' && finding.status === 'FOUND');
  const breaches = (active.results || []).filter((finding) => finding.type === 'breach' && finding.status === 'FOUND');
  const exposures = (active.results || []).filter((finding) => finding.type === 'exposure' && finding.status === 'FOUND');
  const authenticity = Math.min(100, accounts.length * 18 + (active.graph?.edges?.length || 0) * 8);
  const exposureScore = Math.min(100, breaches.length * 20 + exposures.length * 35);
  const identityEvidence = accounts.length
    ? `${accounts.length} public account ${accounts.length === 1 ? 'record' : 'records'} returned; identity fit is not established automatically.`
    : 'No public account records returned.';
  $('#osint-assessment').innerHTML = `<section class="intelligence-assessment">
    <div class="assessment-heading"><p class="eyebrow">Evidence assessment</p><h2>Lookup assessment</h2></div>
    <div class="assessment-grid">
      <article><header><span>Public footprint</span><strong>${authenticity}/100</strong></header><p>${escapeHtml(identityEvidence)}</p><small>${accounts.length ? `${accounts.length} public account records` : 'No public account records'} · ${breaches.length} breach/domain records</small></article>
      <article><header><span>Reported exposure</span><strong>${exposureScore}/100</strong></header><p>${exposures.length ? `${exposures.length} provider exposure ${exposures.length === 1 ? 'record' : 'records'}; raw credentials excluded.` : breaches.length ? `${breaches.length} breach/catalogue records; verify their exact scope.` : 'No verified exposure records returned.'}</p><small>Scores are derived evidence counts, not provider identity or fraud determinations.</small></article>
      <article><header><span>Correlation confidence</span><strong>${Math.round((active.graph?.edges || []).reduce((total, edge) => total + (edge.confidence || 0), 0) / Math.max(1, active.graph?.edges?.length || 0))}%</strong></header><p>${(active.graph?.edges?.length || 0) ? `${active.graph.edges.length} supporting relationship ${active.graph.edges.length === 1 ? 'record' : 'records'} returned.` : 'No supporting relationships generated.'}</p><small>Relationships remain hypotheses until independently corroborated.</small></article>
    </div>
  </section>`;
  $('#osint-export-json').disabled = false;
  $('#osint-export-csv').disabled = false;
  $('#osint-export-html').disabled = false;
  $('#osint-export-pdf').disabled = false;
}

function renderTable(headers, rows, viewName) {
  $('#osint-results-title').textContent = viewName;
  $('#osint-table-head').innerHTML = `<tr>${headers.map((header) => `<th scope="col">${escapeHtml(header)}</th>`).join('')}</tr>`;
  $('#osint-table-body').innerHTML = rows.length ? rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value ?? 'Not available')}</td>`).join('')}</tr>`).join('') : '<tr><td colspan="' + headers.length + '" class="empty-cell"><div class="empty-state"><span class="empty-symbol">⌕</span><strong>No findings</strong><span>This view contains no confirmed or provider-reported records.</span></div></td></tr>';
}

function renderAccountCards() {
  const target = $('#osint-account-cards');
  if (!active) { target.innerHTML = ''; return; }
  const accounts = active.results.filter((finding) => finding.type === 'social_account' && finding.status === 'FOUND');
  target.innerHTML = accounts.length ? accounts.map((finding) => {
    const metadata = finding.metadata || {};
    return `<article class="account-card">
      <header><div><span class="account-platform">${escapeHtml(finding.platform || finding.source)}</span><strong>${escapeHtml(finding.display_name || finding.identifier)}</strong></div><span class="badge">${escapeHtml(finding.status)}</span></header>
      <dl>
        <div><dt>Username</dt><dd>${escapeHtml(finding.identifier)}</dd></div>
        <div><dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}%</dd></div>
        <div><dt>First seen</dt><dd>${escapeHtml(finding.first_seen || 'Not available')}</dd></div>
        <div><dt>Last seen</dt><dd>${escapeHtml(finding.last_seen || 'Not available')}</dd></div>
        ${metadata.location ? `<div><dt>Location</dt><dd>${escapeHtml(metadata.location)}</dd></div>` : ''}
        ${metadata.biography ? `<div class="account-biography"><dt>Biography</dt><dd>${escapeHtml(metadata.biography)}</dd></div>` : ''}
      </dl>
      ${finding.profile_url ? `<a class="account-profile-link" href="${escapeHtml(finding.profile_url)}" target="_blank" rel="noopener noreferrer">Open public profile ↗</a>` : '<span class="account-profile-link disabled">Profile URL unavailable</span>'}
    </article>`;
  }).join('') : '<p class="empty-copy">No public account records to display.</p>';
}

function renderResults(view) {
  if (!active) {
    renderTable(['Type', 'Identifier', 'Source', 'Status'], [], 'No active investigation');
    return;
  }
  if (view === 'email') {
    const rows = active.results.filter((finding) => finding.identifier?.includes('@')).map((finding) => [finding.type, finding.identifier, finding.source, finding.status, finding.verification_status || '—']);
    renderTable(['Type', 'Identifier', 'Source', 'Status', 'Verification'], rows, 'Email Intelligence');
  } else if (view === 'username') {
    const rows = active.results.filter((finding) => finding.type === 'social_account').map((finding) => [finding.platform || finding.source, finding.identifier, finding.display_name, finding.profile_url, finding.source, finding.status]);
    renderAccountCards();
    renderTable(['Platform', 'Username', 'Display name', 'Profile URL', 'Source', 'Status'], rows, 'Username Intelligence');
  } else if (view === 'breaches') {
    const rows = active.results.filter((finding) => finding.type === 'breach').map((finding) => [finding.metadata.breach_name, finding.metadata.organisation, finding.metadata.breach_date, finding.metadata.published_date, (finding.metadata.data_classes || []).join(', '), finding.source, finding.verification_status]);
    renderTable(['Breach', 'Organisation', 'Occurrence', 'Publication', 'Exposed data', 'Source', 'Verification'], rows, 'Breach Intelligence');
  } else if (view === 'exposure') {
    const rows = active.results.filter((finding) => finding.type === 'exposure').map((finding) => [finding.source, finding.metadata.associated_domain, finding.first_seen, finding.last_seen, finding.source_url, finding.confidence]);
    renderTable(['Provider', 'Associated domain', 'First observation', 'Last observation', 'Source', 'Confidence'], rows, 'Infostealer Exposure');
  } else if (view === 'timeline') {
    const rows = (active.timeline || []).map((event) => [event.date, event.date_type, event.type, event.label, event.source]);
    renderTable(['Date', 'Date meaning', 'Event type', 'Description', 'Source'], rows, 'Investigation Timeline');
  } else if (view === 'history') renderHistory();
  else if (view === 'reports') renderReports();
  else {
    renderTable(['Type', 'Identifier', 'Source', 'Status', 'Confidence'], active.results.map((finding) => [finding.type, finding.identifier, finding.source, finding.status, finding.confidence]), 'All findings');
  }
}

function renderGraph() {
  if (!active) { $('#osint-graph').innerHTML = '<p class="empty-copy">Start an investigation to generate relationships.</p>'; return; }
  const graph = active.graph || { nodes: [], edges: [] };
  if (!graph.nodes.length) { $('#osint-graph').innerHTML = '<p class="empty-copy">No relationship data is available for the current findings.</p>'; return; }
  const width = 760;
  const height = 420;
  const nodes = graph.nodes.map((node, index) => ({ ...node, x: 100 + (index % 4) * 190, y: 90 + (Math.floor(index / 4) * 120) }));
  const positions = new Map(nodes.map((node) => [node.id, node]));
  const svgLines = graph.edges.map((edge) => {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) return '';
    return `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" data-confidence="${edge.confidence}" /><title>${escapeHtml(edge.explanation)}</title>`;
  }).join('');
  $('#osint-graph').innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="group" aria-label="Identity relationship graph"><g>${svgLines}</g>${nodes.map((node) => `<g class="graph-node" data-node="${escapeHtml(node.id)}" tabindex="0" role="button" aria-label="${escapeHtml(node.type)} ${escapeHtml(node.label)}"><circle cx="${node.x}" cy="${node.y}" r="38"/><text x="${node.x}" y="${node.y + 54}" text-anchor="middle">${escapeHtml(node.label.slice(0, 24))}</text></g>`).join('')}</svg><div id="graph-detail" class="graph-detail">Select a node or edge for relationship context.</div>`;
  $('#osint-graph').querySelectorAll('.graph-node').forEach((element) => element.addEventListener('click', () => {
    const node = nodes.find((item) => item.id === element.dataset.node);
    const edges = graph.edges.filter((edge) => edge.source === node.id || edge.target === node.id);
    $('#graph-detail').innerHTML = edges.length ? edges.map((edge) => `<p><strong>${escapeHtml(edge.type)}</strong> · ${escapeHtml(edge.confidence)}%<br>${escapeHtml(edge.explanation)}<br><span>Evidence: ${escapeHtml(edge.evidence)}</span></p>`).join('') : `<p>${escapeHtml(node.type)}: ${escapeHtml(node.label)} — no corroborating relationship in this investigation.</p>`;
  }));
  $('#osint-graph').querySelectorAll('line').forEach((line) => line.addEventListener('click', () => {
    $('#graph-detail').textContent = line.querySelector('title')?.textContent || 'Relationship evidence unavailable.';
  }));
}

async function refreshProviders() {
  const target = $('#osint-provider-settings');
  try {
    const data = await request('/api/osint/providers');
    const labels = { ready: 'Available', available: 'Available', disabled: 'Disabled', unavailable: 'Temporarily unavailable', requires_key: 'Requires API key', requires_paid_subscription: 'Requires paid subscription' };
    target.innerHTML = data.providers.map((provider) => `<article class="provider-card"><div><strong>${escapeHtml(provider.name)}</strong><small>${escapeHtml(provider.category)} · ${escapeHtml(provider.cost || '$0')}</small></div><span class="badge ${provider.status === 'ready' || provider.status === 'available' ? '' : 'possible'}">${escapeHtml(labels[provider.status] || provider.status)}</span></article>`).join('');
  } catch (error) {
    target.textContent = error.kind === 'config' ? 'Configure the Worker API before checking providers.' : error.message;
  }
}

async function startInvestigation() {
  const identifiers = $('#osint-identifiers').value.split(/[\n,;]+/).map((value) => value.trim()).filter(Boolean);
  if (!identifiers.length) { $('#osint-run-status').textContent = 'Enter at least one email address or username.'; $('#osint-run-status').className = 'inline-status error'; return; }
  const providers = [...document.querySelectorAll('input[name="osint-provider"]:checked')].map((input) => input.value);
  $('#osint-run-status').textContent = 'Starting provider jobs…';
  $('#osint-run-status').className = 'inline-status';
  try {
    const password = $('#osint-password').value;
    let passwordHashPrefix = null;
    let passwordHashSuffix = null;
    if (password) {
      const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
      const sha1 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
      passwordHashPrefix = sha1.slice(0, 5);
      passwordHashSuffix = sha1.slice(5);
      $('#osint-password').value = '';
    }
    active = await request('/api/osint/investigations', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ identifiers, providers, mode: $('#osint-mode').value, password_hash_prefix: passwordHashPrefix, password_hash_suffix: passwordHashSuffix }) });
    investigationHistory = [active, ...investigationHistory.filter((item) => item.id !== active.id)];
    renderSummary();
    setTab('overview');
    $('#osint-run-status').textContent = `Investigation ${active.id} is ${active.status}.`;
    $('#osint-run-status').className = 'inline-status success';
  } catch (error) {
    $('#osint-run-status').textContent = error.message;
    $('#osint-run-status').className = 'inline-status error';
  }
}

async function refreshActive() {
  if (!active) return;
  try {
    active = await request(`/api/osint/investigations/${active.id}`);
    renderSummary();
    if (activeResultTab !== 'overview') renderResults(activeResultTab);
  } catch (error) {
    $('#osint-run-status').textContent = error.message;
  }
}

function renderHistory() {
  if (!investigationHistory.length) { renderTable(['Investigation', 'Status', 'Created', 'Findings'], [], 'Investigation History'); return; }
  renderTable(['Investigation', 'Status', 'Created', 'Findings'], investigationHistory.map((item) => [item.id, item.status, item.created_at, item.summary?.total_findings || 0]), 'Investigation History');
}

function renderReports() {
  if (!active) { renderTable(['Report', 'Status'], [], 'Reports'); return; }
  renderTable(['Report', 'Format', 'Status'], [['Investigation report', 'JSON', 'Available'], ['Investigation report', 'CSV', 'Available'], ['Investigation report', 'HTML', 'Available'], ['Investigation report', 'Print / PDF', 'Available']], 'Reports');
}

function exportJson() {
  if (active) download(`osint-investigation-${active.id}.json`, JSON.stringify(active, null, 2), 'application/json');
}

function exportCsv() {
  if (!active) return;
  const rows = active.results.map((finding) => ({
    id: finding.id, investigation_id: finding.investigation_id, type: finding.type, identifier: finding.identifier,
    platform: finding.platform, display_name: finding.display_name, profile_url: finding.profile_url,
    source: finding.source, source_url: finding.source_url, status: finding.status, confidence: finding.confidence,
    first_seen: finding.first_seen, last_seen: finding.last_seen, collected_at: finding.collected_at,
  }));
  download(`osint-investigation-${active.id}.csv`, csvRows(rows), 'text/csv');
}

function reportHtml() {
  if (!active) return '';
  const findings = active.results.map((finding) => {
    const metadata = Object.entries(finding.metadata || {})
      .filter(([, value]) => value !== null && value !== undefined && value !== '')
      .map(([key, value]) => `<li><strong>${escapeHtml(key.replace(/_/g, ' '))}:</strong> ${escapeHtml(Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : value)}</li>`).join('');
    return `<tr><td>${escapeHtml(finding.type)}</td><td>${escapeHtml(finding.identifier)}</td><td>${escapeHtml(finding.platform || '—')}</td><td>${escapeHtml(finding.display_name || '—')}</td><td>${escapeHtml(finding.status)}</td><td>${escapeHtml(finding.confidence)}%</td><td><strong>${escapeHtml(finding.source)}</strong><br>${finding.source_url ? `<a href="${escapeHtml(finding.source_url)}">${escapeHtml(finding.source_url)}</a>` : 'No source URL'}<ul>${metadata}</ul></td></tr>`;
  }).join('');
  const evidence = active.results.map((finding) => `<li><strong>${escapeHtml(finding.source)}</strong> — ${escapeHtml(finding.source_url || 'No source URL')}<br>Collected: ${escapeHtml(finding.collected_at)} · Confidence: ${escapeHtml(finding.confidence)}% · ID: ${escapeHtml(finding.id)}</li>`).join('');
  const providers = (active.provider_jobs || []).map((job) => `<tr><td>${escapeHtml(job.provider)}</td><td>${escapeHtml(job.status)}</td><td>${escapeHtml(job.started_at || '—')}</td><td>${escapeHtml(job.completed_at || 'Pending / unfinished')}</td><td>${escapeHtml(job.error || '—')}</td></tr>`).join('');
  const identifiers = (active.identifiers || []).map((identifier) => `<li><strong>${escapeHtml(identifier.type)}:</strong> ${escapeHtml(identifier.value)}</li>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>OSINT Investigation ${escapeHtml(active.id)}</title><style>
    @page{size:A4;margin:14mm}body{font-family:Arial,sans-serif;color:#17212b;font-size:11px;line-height:1.45;margin:0}header{border-bottom:3px solid #70dbc2;padding-bottom:10px;margin-bottom:16px}h1{font-size:24px;margin:0 0 4px}h2{font-size:15px;margin:20px 0 8px;border-bottom:1px solid #ccd5da;padding-bottom:5px}table{width:100%;border-collapse:collapse;margin:8px 0 14px}th,td{border:1px solid #ccd5da;padding:7px;text-align:left;vertical-align:top}th{background:#eef3f5;font-size:10px}tr{break-inside:avoid}.warning{background:#fff3cd;border-left:4px solid #b58a2b;padding:10px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.card{border:1px solid #ccd5da;padding:8px}.card span{display:block;color:#5d6b75;font-size:9px;text-transform:uppercase}.card strong{font-size:14px}ul{margin:5px 0;padding-left:18px}a{color:#236c9f;overflow-wrap:anywhere}@media print{.no-print{display:none!important}body{margin:0}.warning{break-inside:avoid}}
  </style></head><body><header><h1>OSINT Investigation Report</h1><div>Ransom Intel · ${escapeHtml(active.created_at)} → ${escapeHtml(active.updated_at)}</div></header>
  <div class="warning"><strong>Analytical caution:</strong> Provider results are not confirmation of identity or wrongdoing. Public cross-platform matches and catalogue-domain matches require independent corroboration. Raw stealer logs and sensitive credentials are excluded.</div>
  <h2>Investigation details</h2><div class="grid"><div class="card"><span>Investigation ID</span><strong>${escapeHtml(active.id)}</strong></div><div class="card"><span>Status</span><strong>${escapeHtml(active.status)}</strong></div><div class="card"><span>Mode</span><strong>${escapeHtml(active.mode)}</strong></div><div class="card"><span>Identifiers</span><strong>${(active.identifiers || []).length}</strong></div><div class="card"><span>Providers</span><strong>${escapeHtml(active.summary.total_providers)}</strong></div><div class="card"><span>Findings</span><strong>${escapeHtml(active.summary.total_findings)}</strong></div></div>
  <h2>Search identifiers</h2><ul>${identifiers}</ul>
  <h2>Provider status</h2><table><thead><tr><th>Provider</th><th>Status</th><th>Started</th><th>Finished</th><th>Error</th></tr></thead><tbody>${providers}</tbody></table>
  <h2>Findings and evidence</h2><table><thead><tr><th>Type</th><th>Identifier</th><th>Platform</th><th>Display name</th><th>Status</th><th>Confidence</th><th>Source and metadata</th></tr></thead><tbody>${findings || '<tr><td colspan="7">No findings returned.</td></tr>'}</tbody></table>
  <h2>Timeline</h2><table><thead><tr><th>Date</th><th>Date meaning</th><th>Event</th><th>Source</th></tr></thead><tbody>${(active.timeline || []).map((event) => `<tr><td>${escapeHtml(event.date)}</td><td>${escapeHtml(event.date_type)}</td><td>${escapeHtml(event.label)}</td><td>${escapeHtml(event.source)}</td></tr>`).join('') || '<tr><td colspan="4">No timeline events.</td></tr>'}</tbody></table>
  <h2>Relationships</h2>${(active.graph?.edges || []).map((edge) => `<p><strong>${escapeHtml(edge.source)} → ${escapeHtml(edge.target)}</strong><br>${escapeHtml(edge.type)} · ${escapeHtml(edge.confidence)}% confidence<br>${escapeHtml(edge.explanation)}<br>Evidence: ${escapeHtml(edge.evidence)}</p>`).join('') || '<p>No relationships generated.</p>'}
  <h2>Evidence register</h2><ul>${evidence || '<li>No evidence records returned.</li>'}</ul>
  <h2>Provider limitations</h2><ul><li>Not every provider is enabled or available in a zero-cost configuration.</li><li>Failed, unavailable, and rate-limited requests must not be interpreted as negative findings.</li><li>Maigret and infostealer providers may require external execution or licensed access.</li><li>Dates retain provider meanings: breach occurrence, publication, first/last observation, and collection time are separate.</li></ul>
  </body></html>`;
}

function exportHtml() {
  if (!active) return;
  download(`osint-investigation-${active.id}.html`, reportHtml(), 'text/html');
}

function printPdf() {
  if (!active) return;
  const blob = new Blob([reportHtml()], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const printWindow = window.open(url, '_blank');
  if (printWindow) {
    printWindow.addEventListener('load', () => setTimeout(() => printWindow.print(), 250), { once: true });
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    return;
  }
  const frame = document.createElement('iframe');
  frame.hidden = true;
  frame.title = 'OSINT print report';
  frame.src = url;
  document.body.appendChild(frame);
  frame.addEventListener('load', () => {
    setTimeout(() => {
      try {
        frame.contentWindow.focus();
        frame.contentWindow.print();
      } catch {
        window.open(url, '_blank', 'noopener,noreferrer');
      } finally {
        setTimeout(() => {
          frame.remove();
          URL.revokeObjectURL(url);
        }, 1000);
      }
    }, 250);
  }, { once: true });
}

async function importIdentifiers(file) {
  if (!file) return;
  const text = await file.text();
  let values = [];
  if (file.name.toLowerCase().endsWith('.json')) {
    const data = JSON.parse(text);
    values = Array.isArray(data) ? data : data.identifiers || data.emails || data.usernames || [];
  } else {
    values = text.split(/\r?\n/).flatMap((line) => line.split(',')).map((value) => value.trim().replace(/^"|"$/g, '')).filter(Boolean);
  }
  $('#osint-identifiers').value = values.join('\n');
  $('#osint-run-status').textContent = `Imported ${values.length} identifier rows; duplicates are removed during submission.`;
}

export function initOsint() {
  const tabs = [...document.querySelectorAll('[data-osint-tab]')];
  const showModule = (moduleName) => {
    const isOsint = moduleName === 'osint';
    $('#ransomware-module').hidden = isOsint;
    $('#osint-module').hidden = !isOsint;
    $('#module-subtitle').textContent = isOsint ? 'OSINT investigation' : 'Victim claim search';
    $('#ransomware-nav').setAttribute('aria-current', isOsint ? 'false' : 'page');
    $('#ransomware-nav').hidden = isOsint;
    $('#open-osint').setAttribute('aria-current', isOsint ? 'page' : 'false');
    $('#open-osint').hidden = isOsint;
  };
  const syncRoute = () => {
    const hash = window.location.hash || '#/ransomware';
    if (hash.startsWith('#/osint')) {
      showModule('osint');
      const tabName = hash.split('/')[2] || 'new';
      if (tabs.some((tab) => tab.dataset.osintTab === tabName)) setTab(tabName);
      else setTab('new');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      showModule('ransomware');
    }
  };
  window.addEventListener('hashchange', syncRoute);
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => setTab(tab.dataset.osintTab));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const index = tabs.indexOf(tab);
      const next = event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? tabs.length - 1
          : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      setTab(tabs[next].dataset.osintTab);
      tabs[next].focus({ preventScroll: true });
      tabs[next].scrollIntoView({ block: 'nearest', inline: 'nearest', container: 'nearest' });
    });
  });
  document.querySelectorAll('.primary-nav a').forEach((link) => link.addEventListener('click', () => {
    const isOsint = link.id === 'open-osint';
    showModule(isOsint ? 'osint' : 'ransomware');
  }));
  $('#open-osint').addEventListener('click', refreshProviders);
  $('#osint-new').addEventListener('click', () => setTab('new'));
  $('#osint-refresh').addEventListener('click', refreshActive);
  $('#osint-form').addEventListener('submit', (event) => { event.preventDefault(); startInvestigation(); });
  $('#osint-quick-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const identifier = $('#osint-quick-input').value.trim();
    if (!identifier) return;
    $('#osint-identifiers').value = identifier;
    setTab('new');
    void startInvestigation();
  });
  $('#osint-import-button').addEventListener('click', () => $('#osint-import').click());
  $('#osint-import').addEventListener('change', () => importIdentifiers($('#osint-import').files[0]).catch((error) => { $('#osint-run-status').textContent = `Import failed: ${error.message}`; }));
  $('#osint-provider-refresh').addEventListener('click', refreshProviders);
  $('#osint-export-json').addEventListener('click', exportJson);
  $('#osint-export-csv').addEventListener('click', exportCsv);
  $('#osint-export-html').addEventListener('click', exportHtml);
  $('#osint-export-pdf').addEventListener('click', printPdf);
  document.querySelector('.brand').addEventListener('click', () => showModule('ransomware'));
  syncRoute();
  renderSummary();
}
