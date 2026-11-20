import './config.js';
import { matchRecords, normalizeName, SOURCES } from './normalize.js';
import { clearResponseCache, purgeExpiredCache, cachedResponseCount } from './adapters/common.js';
import { ransomlookAdapter } from './adapters/ransomlookAdapter.js';
import { ransomfeedAdapter } from './adapters/ransomfeedAdapter.js';
import { ransomwareLiveAdapter } from './adapters/ransomwareLiveAdapter.js';
import { csvContent, jsonContent } from './export.js';

const $ = (selector) => document.querySelector(selector);
const searchForm = $('#search-form');
const queryInput = $('#query');
const sourceStatus = $('#statuses');
const tableWrap = $('#table-wrap');
const resultBody = $('#results');
const settingsDialog = $('#settings-dialog');
const detailDialog = $('#detail-dialog');

let allRecords = [];
let matchedGroups = [];
let currentPage = 0;
let lastQuery = '';
let lastExact = false;
let lastSearch = null;
let toastTimer;

purgeExpiredCache();

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));

function toast(message) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 3000);
}

function renderSourceStatus(states = {}) {
  sourceStatus.innerHTML = SOURCES.map((name) => {
    const state = states[name] || { state: 'ready', label: 'Not searched', count: null };
    const resultLabel = state.count === null || state.count === undefined
      ? state.label
      : `${state.label} · ${state.count}`;
    const errorText = state.message
      ? `<small class="source-error">${escapeHtml(state.message)}</small>`
      : '';
    return `<article class="status-card">
      <span class="status-name">${escapeHtml(name)}</span>
      <span class="status-copy"><span class="status-result ${escapeHtml(state.state)}">${escapeHtml(resultLabel)}</span>${errorText}</span>
    </article>`;
  }).join('');
}

function formatDate(value) {
  if (!value) return 'Not available';
  return escapeHtml(String(value).replace('T', ' ').replace(/\.\d+.*$/, '').replace(/\+00:00$/, ''));
}

function setFacetOptions(selector, label, values) {
  const select = $(selector);
  const current = select.value;
  const unique = [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
  select.innerHTML = `<option value="all">All ${label}</option>${unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('')}`;
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

function updateFacets() {
  setFacetOptions('#country-filter', 'countries', allRecords.map((record) => record.country));
  setFacetOptions('#group-filter', 'groups', allRecords.map((record) => record.threat_group));
  setFacetOptions('#industry-filter', 'industries', allRecords.map((record) => record.industry));
}

function activeFilterCount() {
  const selectFilters = ['#source-filter', '#country-filter', '#group-filter', '#industry-filter', '#duplicate-filter'];
  const selected = selectFilters.filter((selector) => $(selector).value !== 'all').length;
  const dateRange = $('#date-from').value || $('#date-to').value ? 1 : 0;
  const evidence = $('#with-screenshot').checked ? 1 : 0;
  const website = $('#with-website').checked ? 1 : 0;
  return selected + dateRange + evidence + website;
}

function renderEmptyState(title, description) {
  resultBody.innerHTML = `<tr><td colspan="8" class="empty-cell"><div class="empty-state">
    <span class="empty-symbol" aria-hidden="true">⌕</span>
    <strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span>
  </div></td></tr>`;
}

function renderResults() {
  const filters = {
    source: $('#source-filter').value,
    country: $('#country-filter').value,
    group: $('#group-filter').value,
    industry: $('#industry-filter').value,
    matchStatus: $('#duplicate-filter').value,
    from: $('#date-from').value,
    to: $('#date-to').value,
    evidence: $('#with-screenshot').checked,
    website: $('#with-website').checked,
  };

  const visibleGroups = matchedGroups.filter((group) => {
    const records = group.records;
    const dateMatches = records.some((record) => {
      const date = (record.attack_date || record.discovery_date || record.publication_date || '').slice(0, 10);
      return (!filters.from || date >= filters.from) && (!filters.to || date <= filters.to);
    });
    return (filters.source === 'all' || group.sources.includes(filters.source))
      && (filters.country === 'all' || records.some((record) => record.country === filters.country))
      && (filters.group === 'all' || records.some((record) => record.threat_group === filters.group))
      && (filters.industry === 'all' || records.some((record) => record.industry === filters.industry))
      && (filters.matchStatus === 'all' || group.match_status === filters.matchStatus)
      && ((!filters.from && !filters.to) || dateMatches)
      && (!filters.evidence || records.some((record) => record.screenshot_url))
      && (!filters.website || records.some((record) => record.website || record.domain));
  });

  const sortMode = $('#sort').value;
  if (sortMode === 'victim') visibleGroups.sort((a, b) => a.victim_name.localeCompare(b.victim_name));
  if (sortMode === 'newest') visibleGroups.sort((a, b) => (b.latest_discovery || '').localeCompare(a.latest_discovery || ''));

  const pageSize = Number($('#page-size').value) || 25;
  const pageCount = Math.max(1, Math.ceil(visibleGroups.length / pageSize));
  currentPage = Math.min(currentPage, pageCount - 1);
  const activeCount = activeFilterCount();
  $('#active-filter-count').textContent = `${activeCount} active`;
  $('#active-filter-count').classList.toggle('active', activeCount > 0);
  $('#reset-filters').disabled = activeCount === 0;
  $('#result-count').textContent = `${allRecords.length} source records · ${visibleGroups.length} matched groups`;
  $('#page-info').textContent = visibleGroups.length ? `Page ${currentPage + 1} of ${pageCount}` : 'No matching results';
  $('#prev').disabled = currentPage === 0 || visibleGroups.length === 0;
  $('#next').disabled = currentPage >= pageCount - 1 || visibleGroups.length === 0;
  $('#export-csv').disabled = allRecords.length === 0;
  $('#export-json').disabled = allRecords.length === 0;
  $('#refresh-search').disabled = !lastQuery;

  const pageGroups = visibleGroups.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  if (!pageGroups.length) {
    renderEmptyState(
      matchedGroups.length ? 'No results match these filters' : (lastQuery ? 'No claims found' : 'Search public reporting'),
      matchedGroups.length ? 'Clear one or more filters to broaden the results.' : (lastQuery ? 'Try a shorter name, domain, or threat group.' : 'Enter a term above to search the configured sources.'),
    );
    return;
  }

  resultBody.innerHTML = pageGroups.map((group) => {
    const records = filters.source === 'all'
      ? group.records
      : group.records.filter((record) => record.source_name === filters.source);
    const column = (key) => [...new Set(records.map((record) => record[key]).filter(Boolean))].join(' / ') || 'Not available';
    const sourceCount = new Set(records.map((record) => record.source_name)).size;
    const groupIndex = matchedGroups.indexOf(group);
    return `<tr>
      <td><button type="button" class="victim-link" data-details="${groupIndex}" aria-label="View details for ${escapeHtml(group.victim_name)}">${escapeHtml(group.victim_name)}</button>${group.domain ? `<div class="record-subline"><button type="button" class="copy-link" data-copy="${escapeHtml(group.domain)}" aria-label="Copy domain ${escapeHtml(group.domain)}">${escapeHtml(group.domain)}</button></div>` : ''}</td>
      <td>${formatDate(column('attack_date'))}</td>
      <td>${formatDate(column('discovery_date'))}</td>
      <td>${escapeHtml(column('threat_group'))}</td>
      <td>${escapeHtml(column('country'))}</td>
      <td>${escapeHtml(column('industry'))}</td>
      <td><span class="badge">${sourceCount} ${sourceCount === 1 ? 'source' : 'sources'}</span></td>
      <td><span class="badge ${group.match_status === 'possible' ? 'possible' : ''}">${escapeHtml(group.match_status)}</span></td>
    </tr>`;
  }).join('');
}

function setStatusMessage(element, message, tone = '') {
  element.textContent = message;
  element.classList.remove('success', 'error');
  if (tone) element.classList.add(tone);
}

async function copyText(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    toast(successMessage);
  } catch {
    toast('Clipboard access is unavailable in this browser.');
  }
}

function openDetails(group) {
  const recordMarkup = group.records.map((record) => {
    const fields = [
      ['Website', record.website], ['Domain', record.domain], ['Country', record.country],
      ['Industry', record.industry], ['Threat group', record.threat_group], ['Attack date', record.attack_date],
      ['Discovery date', record.discovery_date], ['Publication date', record.publication_date],
      ['Last updated', record.last_updated], ['Record ID', record.source_record_id],
    ];
    const fieldMarkup = fields.map(([label, value]) => `<div class="detail-field"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || 'Not available')}${value && (label === 'Website' || label === 'Domain') ? ` <button type="button" class="copy-link" data-copy="${escapeHtml(value)}" aria-label="Copy ${escapeHtml(label.toLowerCase())}">Copy</button>` : ''}</dd></div>`).join('');
    const sourceLink = record.original_record_url
      ? `<a href="${escapeHtml(record.original_record_url)}" target="_blank" rel="noopener noreferrer">Open original record ↗</a>`
      : 'Not available';
    const screenshot = record.screenshot_url
      ? `<a href="${escapeHtml(record.screenshot_url)}" target="_blank" rel="noopener noreferrer"><img class="detail-image" loading="lazy" src="${escapeHtml(record.screenshot_url)}" alt="Evidence supplied by ${escapeHtml(record.source_name)}"></a>`
      : '<p class="detail-note">No screenshot was supplied by this source.</p>';
    return `<section class="detail-section"><h3>${escapeHtml(record.source_name)} <span>Source record</span></h3>
      <dl class="detail-grid">${fieldMarkup}<div class="detail-field"><dt>Original record</dt><dd>${sourceLink}</dd></div></dl>
      <p>${escapeHtml(record.description || 'No description supplied by this source.')}</p>${screenshot}</section>`;
  }).join('');

  $('#detail-content').innerHTML = `<p class="eyebrow">Victim claim details</p><h2 id="detail-dialog-title" class="detail-title">${escapeHtml(group.victim_name)}</h2>
    <p class="detail-meta">${group.records.length} source records · ${escapeHtml(group.match_status)} match · claims remain unverified</p>${recordMarkup}`;
  detailDialog.showModal();
}

function classifyError(error) {
  if (error.kind === 'config') return { state: 'error', label: 'Worker not configured' };
  if (error.kind === 'auth') return { state: 'error', label: 'Authentication failed' };
  if (error.kind === 'rate') return { state: 'error', label: 'Rate limited' };
  if (error.kind === 'timeout') return { state: 'error', label: 'Timed out' };
  if (error.kind === 'invalid') return { state: 'error', label: 'Invalid response' };
  if (error.kind === 'cors') return { state: 'error', label: 'Worker connection failed' };
  return { state: 'error', label: error.status ? `HTTP ${error.status}` : 'API unavailable' };
}

async function search(query, exact, force = false) {
  const normalizedQuery = query.trim().normalize('NFKC').replace(/\s+/g, ' ');
  if (normalizedQuery.length < 2 || normalizedQuery.length > 120 || /[\u0000-\u001f\u007f]/.test(normalizedQuery)) {
    toast('Enter between 2 and 120 characters.');
    queryInput.focus();
    return;
  }

  lastQuery = normalizedQuery;
  lastExact = exact;
  lastSearch = null;
  currentPage = 0;
  $('#search-button').disabled = true;
  $('#search-button').innerHTML = '<span class="spinner" aria-hidden="true"></span> Searching';
  $('#results-heading').textContent = `Searching “${normalizedQuery}”`;
  $('#search-meta').textContent = 'Requesting available source records…';
  $('#refresh-search').disabled = true;
  tableWrap.setAttribute('aria-busy', 'true');
  resultBody.innerHTML = '<tr><td colspan="8" class="empty-cell"><span class="loading-state"><span class="spinner" aria-hidden="true"></span>Searching independent reporting sources…</span></td></tr>';
  renderSourceStatus(Object.fromEntries(SOURCES.map((source) => [source, { state: 'loading', label: 'Searching', count: null }])));

  const startedAt = performance.now();
  const calls = [
    ['RansomLook', () => ransomlookAdapter(normalizedQuery, { force })],
    ['RansomFeed', () => ransomfeedAdapter(normalizedQuery, { force })],
    ['Ransomware.live Pro', () => ransomwareLiveAdapter(normalizedQuery, '', { force })],
  ];
  const results = await Promise.all(calls.map(async ([name, request]) => {
    try { return { name, result: await request() }; }
    catch (error) { return { name, error }; }
  }));

  allRecords = [];
  const states = {};
  let cachedSources = 0;
  for (const { name, result, error } of results) {
    if (error) {
      states[name] = { ...classifyError(error), count: null, message: error.message };
      continue;
    }
    let records = result.records;
    if (exact) records = records.filter((record) => record.normalized_victim_name === normalizeName(normalizedQuery));
    allRecords.push(...records);
    states[name] = { state: 'ok', label: result.cached ? 'Cached' : 'Connected', count: records.length };
    if (result.cached) cachedSources += 1;
  }

  matchedGroups = matchRecords(allRecords);
  updateFacets();
  const duration = Math.round(performance.now() - startedAt);
  const connected = Object.values(states).filter((state) => state.state === 'ok').length;
  const timingText = `Searched ${new Date().toLocaleString()} · ${duration} ms`;
  $('#results-heading').textContent = allRecords.length ? `Results for “${normalizedQuery}”` : `Search complete for “${normalizedQuery}”`;
  $('#search-meta').textContent = `${timingText} · ${connected}/${SOURCES.length} sources responded${cachedSources ? ` · ${cachedSources} cached` : ''}`;
  lastSearch = { query: normalizedQuery, exact, searched_at: new Date().toISOString(), duration_ms: duration, states, cached_sources: cachedSources };
  renderSourceStatus(states);
  tableWrap.setAttribute('aria-busy', 'false');
  renderResults();
  $('#search-button').disabled = false;
  $('#search-button').innerHTML = 'Search <span aria-hidden="true">↗</span>';
}

function resetFilters() {
  for (const selector of ['#source-filter', '#country-filter', '#group-filter', '#industry-filter', '#duplicate-filter']) $(selector).value = 'all';
  $('#date-from').value = '';
  $('#date-to').value = '';
  $('#with-screenshot').checked = false;
  $('#with-website').checked = false;
  currentPage = 0;
  renderResults();
}

function resetSearch() {
  queryInput.value = '';
  lastQuery = '';
  lastExact = false;
  lastSearch = null;
  allRecords = [];
  matchedGroups = [];
  currentPage = 0;
  resetFilters();
  updateFacets();
  renderSourceStatus();
  $('#results-heading').textContent = 'Ready when you are';
  $('#search-meta').textContent = 'Enter a term to search the configured sources.';
  renderResults();
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1200);
}

async function testWorkerConnection() {
  const button = $('#test-key');
  const status = $('#key-status');
  const base = (window.RI_CONFIG?.apiBase || '').replace(/\/$/, '');
  button.disabled = true;
  status.setAttribute('aria-busy', 'true');
  setStatusMessage(status, 'Checking the Worker health endpoint…');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    if (!base || base.includes('YOUR-WORKER')) throw new Error('Set the Worker URL in src/config.js, then rebuild and publish the site.');
    const response = await fetch(`${base}/api/health`, { headers: { Accept: 'application/json' }, signal: controller.signal });
    if (response.status === 403) throw new Error('The Worker rejected this site’s origin. Add the site URL to ALLOWED_ORIGINS and redeploy the Worker.');
    if (!response.ok) throw new Error(`The Worker returned HTTP ${response.status}.`);
    const health = await response.json();
    if (health.status !== 'ok') throw new Error('The Worker responded, but its health status was not OK.');
    setStatusMessage(status, `Worker connected · Pro API key ${health.pro_key_configured ? 'configured' : 'not configured'}.`, 'success');
  } catch (error) {
    const message = error.name === 'AbortError'
      ? 'The Worker health check timed out. Try again in a moment.'
      : error instanceof TypeError
        ? 'Could not reach the Worker. Check its URL and this site’s allowed origin.'
        : error.message;
    setStatusMessage(status, message, 'error');
  } finally {
    clearTimeout(timeout);
    button.disabled = false;
    status.setAttribute('aria-busy', 'false');
  }
}

searchForm.addEventListener('submit', (event) => {
  event.preventDefault();
  void search(queryInput.value, $('#exact').checked);
});
$('#refresh-search').addEventListener('click', () => void search(lastQuery, lastExact, true));

for (const selector of ['#source-filter', '#country-filter', '#group-filter', '#industry-filter', '#duplicate-filter', '#sort', '#with-screenshot', '#with-website', '#date-from', '#date-to', '#page-size']) {
  $(selector).addEventListener('change', () => { currentPage = 0; renderResults(); });
}
$('#reset-filters').addEventListener('click', resetFilters);
$('#reset-search').addEventListener('click', resetSearch);
$('#prev').addEventListener('click', () => { if (currentPage > 0) { currentPage -= 1; renderResults(); } });
$('#next').addEventListener('click', () => { currentPage += 1; renderResults(); });

resultBody.addEventListener('click', (event) => {
  const detailsButton = event.target.closest('[data-details]');
  if (detailsButton) openDetails(matchedGroups[Number(detailsButton.dataset.details)]);
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) void copyText(copyButton.dataset.copy, 'Copied to clipboard.');
});
$('#detail-content').addEventListener('click', (event) => {
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) void copyText(copyButton.dataset.copy, 'Copied to clipboard.');
});

$('#export-json').addEventListener('click', () => download(
  new Blob([jsonContent(allRecords, matchedGroups, lastSearch)], { type: 'application/json' }),
  'ransom-intel-results.json',
));
$('#export-csv').addEventListener('click', () => download(
  new Blob([csvContent(allRecords, matchedGroups)], { type: 'text/csv;charset=utf-8' }),
  'ransom-intel-results.csv',
));

$('#open-settings').addEventListener('click', () => {
  $('#cache-minutes').value = localStorage.getItem('ri-cache-minutes') ?? '5';
  $('#default-page-size').value = localStorage.getItem('ri-page-size') ?? '25';
  $('#default-sort').value = localStorage.getItem('ri-sort') ?? 'relevance';
  $('#page-size').value = $('#default-page-size').value;
  $('#sort').value = $('#default-sort').value;
  $('#cache-status').textContent = `${cachedResponseCount()} cached source responses in this browser.`;
  settingsDialog.showModal();
});
$('#test-key').addEventListener('click', () => void testWorkerConnection());
$('#clear-key').addEventListener('click', () => {
  localStorage.removeItem('ri-api-key');
  setStatusMessage($('#key-status'), 'Legacy browser key removed. Worker credentials are managed in Cloudflare.');
});
$('#save-cache').addEventListener('click', () => {
  const raw = Number($('#cache-minutes').value);
  const minutes = Math.min(60, Math.max(0, Number.isFinite(raw) ? raw : 0));
  localStorage.setItem('ri-cache-minutes', String(minutes));
  $('#cache-minutes').value = String(minutes);
  setStatusMessage($('#cache-status'), `Cache duration set to ${minutes} minutes.`, 'success');
});
$('#clear-cache').addEventListener('click', () => {
  clearResponseCache();
  setStatusMessage($('#cache-status'), 'Cached source responses cleared.', 'success');
});
$('#default-page-size').addEventListener('change', () => {
  localStorage.setItem('ri-page-size', $('#default-page-size').value);
  $('#page-size').value = $('#default-page-size').value;
  renderResults();
});
$('#default-sort').addEventListener('change', () => {
  localStorage.setItem('ri-sort', $('#default-sort').value);
  $('#sort').value = $('#default-sort').value;
  renderResults();
});

$('#page-size').value = localStorage.getItem('ri-page-size') || '25';
$('#sort').value = localStorage.getItem('ri-sort') || 'relevance';
renderSourceStatus();
renderResults();
