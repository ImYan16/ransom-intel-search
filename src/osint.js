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
let history = [];
let activeResultTab = 'overview';

function setTab(name) {
  activeResultTab = name;
  document.querySelectorAll('[data-osint-tab]').forEach((tab) => tab.setAttribute('aria-selected', String(tab.dataset.osintTab === name)));
  ['overview', 'new', 'email', 'username', 'breaches', 'exposure', 'relationships', 'timeline', 'history', 'reports'].forEach((panelName) => {
    const panel = panelName === 'new' ? $('#osint-new-panel') : panelName === 'overview' ? $('#osint-overview') : panelName === 'relationships' ? $('#osint-graph-panel') : panelName === 'timeline' || panelName === 'history' || panelName === 'reports' || panelName === 'email' || panelName === 'username' || panelName === 'breaches' || panelName === 'exposure' ? $('#osint-results') : null;
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
    target.innerHTML = data.providers.map((provider) => `<article class="provider-card"><div><strong>${escapeHtml(provider.name)}</strong><small>${escapeHtml(provider.category)}</small></div><span class="badge ${provider.status === 'ready' ? '' : 'possible'}">${escapeHtml(provider.status)}</span></article>`).join('');
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
    active = await request('/api/osint/investigations', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ identifiers, providers, mode: $('#osint-mode').value }) });
    history = [active, ...history.filter((item) => item.id !== active.id)];
    renderSummary();
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
  if (!history.length) { renderTable(['Investigation', 'Status', 'Created', 'Findings'], [], 'Investigation History'); return; }
  renderTable(['Investigation', 'Status', 'Created', 'Findings'], history.map((item) => [item.id, item.status, item.created_at, item.summary?.total_findings || 0]), 'Investigation History');
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
  const findings = active.results.map((finding) => `<li><strong>${escapeHtml(finding.source)}</strong> — ${escapeHtml(finding.type)} / ${escapeHtml(finding.identifier)} — ${escapeHtml(finding.status)} (${escapeHtml(finding.confidence)}%)</li>`).join('');
  const evidence = active.results.map((finding) => `<li>${escapeHtml(finding.source)}: ${escapeHtml(finding.source_url || 'No source URL')} — collected ${escapeHtml(finding.collected_at)}</li>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>OSINT Investigation ${escapeHtml(active.id)}</title><style>body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;color:#17212b}h1{border-bottom:2px solid #344554}.warning{background:#fff3cd;padding:12px}li{margin:8px 0}@media print{body{margin:0}}</style></head><body><h1>OSINT Investigation Report</h1><p><strong>ID:</strong> ${escapeHtml(active.id)}<br><strong>Status:</strong> ${escapeHtml(active.status)}<br><strong>Identifiers:</strong> ${escapeHtml(active.identifiers.map((item) => item.value).join(', '))}</p><p class="warning">Provider limitations and confidence scores are not confirmation of identity. Raw stealer logs and sensitive credentials are excluded.</p><h2>Overview</h2><p>Providers: ${escapeHtml(active.summary.total_providers)} · Successful: ${escapeHtml(active.summary.successful_providers)} · Failed: ${escapeHtml(active.summary.failed_providers)} · Findings: ${escapeHtml(active.summary.total_findings)}</p><h2>Findings</h2><ul>${findings}</ul><h2>Timeline</h2><ul>${(active.timeline || []).map((event) => `<li>${escapeHtml(event.date)} — ${escapeHtml(event.label)} (${escapeHtml(event.date_type)})</li>`).join('')}</ul><h2>Relationships</h2><p>${(active.graph?.edges || []).map((edge) => `${escapeHtml(edge.source)} → ${escapeHtml(edge.target)}: ${escapeHtml(edge.explanation)} (${escapeHtml(edge.confidence)}%)`).join('<br>') || 'No relationships generated.'}</p><h2>Evidence</h2><ul>${evidence}</ul></body></html>`;
}

function exportHtml() {
  if (!active) return;
  download(`osint-investigation-${active.id}.html`, reportHtml(), 'text/html');
}

function printPdf() {
  if (!active) return;
  const printWindow = window.open('', '_blank', 'noopener,noreferrer');
  if (!printWindow) return;
  printWindow.document.open();
  printWindow.document.write(reportHtml());
  printWindow.document.close();
  printWindow.addEventListener('load', () => printWindow.print(), { once: true });
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
  document.querySelectorAll('[data-osint-tab]').forEach((tab) => tab.addEventListener('click', () => setTab(tab.dataset.osintTab)));
  document.querySelectorAll('.primary-nav a').forEach((link) => link.addEventListener('click', () => {
    $('#osint-module').hidden = true;
    $('#ransomware-module').hidden = false;
  }));
  $('#open-osint').addEventListener('click', () => {
    $('#ransomware-module').hidden = true;
    $('#osint-module').hidden = false;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  $('#open-osint').addEventListener('click', refreshProviders);
  $('#osint-new').addEventListener('click', () => setTab('new'));
  $('#osint-refresh').addEventListener('click', refreshActive);
  $('#osint-form').addEventListener('submit', (event) => { event.preventDefault(); startInvestigation(); });
  $('#osint-import-button').addEventListener('click', () => $('#osint-import').click());
  $('#osint-import').addEventListener('change', () => importIdentifiers($('#osint-import').files[0]).catch((error) => { $('#osint-run-status').textContent = `Import failed: ${error.message}`; }));
  $('#osint-provider-refresh').addEventListener('click', refreshProviders);
  $('#osint-export-json').addEventListener('click', exportJson);
  $('#osint-export-csv').addEventListener('click', exportCsv);
  $('#osint-export-html').addEventListener('click', exportHtml);
  $('#osint-export-pdf').addEventListener('click', printPdf);
  document.querySelector('.brand').addEventListener('click', () => { $('#osint-module').hidden = true; $('#ransomware-module').hidden = false; });
  renderSummary();
}
