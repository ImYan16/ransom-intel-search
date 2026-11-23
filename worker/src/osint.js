const investigations = new Map();
const providerCache = new Map();

const iso = () => new Date().toISOString();
const randomId = () => crypto.randomUUID();

function cacheGet(key) {
  const entry = providerCache.get(key);
  if (entry && entry.expires > Date.now()) return entry.value;
  providerCache.delete(key);
  return null;
}

function cacheSet(key, value, ttlMs) {
  providerCache.set(key, { value, expires: Date.now() + ttlMs });
}

export function isValidEmail(value) {
  if (typeof value !== 'string' || value.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u.test(value.trim());
}

export function normalizeUsername(value) {
  if (typeof value !== 'string') return null;
  const username = value.trim().replace(/^@/, '').normalize('NFKC');
  return /^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$/.test(username) ? username : null;
}

function normalizeIdentifier(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return isValidEmail(email) ? { type: 'email', value: email } : normalizeUsername(value) ? { type: 'username', value: normalizeUsername(value) } : null;
}

function providerResult(investigationId, type, identifier, provider, data = {}) {
  return {
    id: randomId(),
    investigation_id: investigationId,
    type,
    identifier,
    platform: data.platform || null,
    display_name: data.display_name || null,
    profile_url: data.profile_url || null,
    source: provider,
    source_url: data.source_url || null,
    status: data.status || 'UNKNOWN',
    confidence: Number.isFinite(data.confidence) ? data.confidence : 0,
    first_seen: data.first_seen || null,
    last_seen: data.last_seen || null,
    collected_at: iso(),
    verification_status: data.verification_status || null,
    metadata: data.metadata || {},
  };
}

async function safeJson(url, options, timeoutMs = 12000) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) {
    const error = new Error(`Provider HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function publicBreachCatalog(email, investigationId) {
  const domain = email.split('@')[1]?.toLowerCase() || '';
  const key = 'public-breach-catalog';
  let breaches = cacheGet(key);
  try {
    if (!breaches) {
      breaches = await safeJson('https://haveibeenpwned.com/api/v3/breaches', {
        headers: { 'user-agent': 'Ransom-Intel-Search' },
      });
      cacheSet(key, breaches, 24 * 60 * 60 * 1000);
    }
  } catch (error) {
    return [providerError(investigationId, 'breach', email, 'Public breach catalogue', error)];
  }
  return breaches
    .filter((breach) => domain && String(breach.Domain || '').toLowerCase() === domain)
    .map((breach) => providerResult(investigationId, 'breach', email, 'Public breach catalogue', {
      status: 'FOUND',
      confidence: 70,
      source_url: breach.Domain ? `https://${breach.Domain}` : 'https://haveibeenpwned.com/',
      verification_status: breach.IsVerified ? 'Confirmed by provider' : 'Reported by source',
      first_seen: breach.BreachDate || null,
      last_seen: breach.BreachDate || null,
      metadata: {
        breach_name: breach.Name,
        organisation: breach.Title,
        breach_date: breach.BreachDate || null,
        published_date: breach.AddedDate || null,
        data_classes: breach.DataClasses || [],
        is_verified: !!breach.IsVerified,
        catalogue_match: 'email domain',
        email_account_not_verified: true,
      },
    }));
}

async function pwnedPasswords(prefix, suffix, investigationId, identifier) {
  if (!/^[A-F0-9]{5}$/.test(prefix) || !/^[A-F0-9]{35}$/.test(suffix)) {
    return providerResult(investigationId, 'password_exposure', identifier, 'HIBP Pwned Passwords', {
      status: 'DISABLED', confidence: 0, metadata: { reason: 'Password hash range was not supplied' },
    });
  }
  const cacheKey = `pwned-password:${prefix}`;
  let text = cacheGet(cacheKey);
  try {
    if (!text) {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'user-agent': 'Ransom-Intel-Search', 'add-padding': 'true' },
        signal: AbortSignal.timeout(12000),
      });
      if (!response.ok) throw Object.assign(new Error(`Provider HTTP ${response.status}`), { status: response.status });
      text = await response.text();
      cacheSet(cacheKey, text, 24 * 60 * 60 * 1000);
    }
  } catch (error) {
    return providerError(investigationId, 'password_exposure', identifier, 'HIBP Pwned Passwords', error);
  }
  const match = text.split(/\r?\n/).find((line) => line.toUpperCase().startsWith(suffix));
  if (!match) return providerResult(investigationId, 'password_exposure', identifier, 'HIBP Pwned Passwords', {
    status: 'NOT_FOUND', confidence: 100, source_url: 'https://haveibeenpwned.com/Passwords',
    verification_status: 'No matching suffix in provider range',
    metadata: { k_anonymity: true, full_password_not_sent: true },
  });
  const count = Number(match.split(':')[1]?.trim()) || 0;
  return providerResult(investigationId, 'password_exposure', identifier, 'HIBP Pwned Passwords', {
    status: 'FOUND', confidence: 100, source_url: 'https://haveibeenpwned.com/Passwords',
    verification_status: 'Confirmed by provider range',
    metadata: { exposure_count: count, k_anonymity: true, full_password_not_sent: true },
  });
}

function providerError(investigationId, type, identifier, provider, error) {
  const status = error.status === 429 ? 'RATE_LIMITED' : 'ERROR';
  return providerResult(investigationId, type, identifier, provider, { status, confidence: 0, metadata: { error: status === 'RATE_LIMITED' ? 'Rate limited by provider' : 'Provider request failed' } });
}

async function hibpEmail(email, investigationId, env) {
  if (!env.HIBP_API_KEY) return providerResult(investigationId, 'breach', email, 'Have I Been Pwned account search', { status: 'DISABLED', metadata: { reason: 'Requires HIBP_API_KEY for account-breach searches' } });
  if (!/^[A-Fa-f0-9]{32}$/.test(env.HIBP_API_KEY.trim())) return providerResult(investigationId, 'breach', email, 'Have I Been Pwned account search', { status: 'ERROR', metadata: { reason: 'HIBP_API_KEY must be a 32-character hexadecimal API key' } });
  const cacheKey = `hibp:${email}`;
  let breaches = cacheGet(cacheKey);
  if (!breaches) {
    try {
      breaches = await safeJson(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
        headers: { 'hibp-api-key': env.HIBP_API_KEY, 'user-agent': 'Ransom-Intel-Search' },
      });
      cacheSet(cacheKey, breaches, 24 * 60 * 60 * 1000);
    } catch (error) {
      if (error.status === 404) {
        breaches = [];
        cacheSet(cacheKey, breaches, 24 * 60 * 60 * 1000);
      } else return providerError(investigationId, 'breach', email, 'Have I Been Pwned', error);
    }
  }
  return breaches.map((breach) => providerResult(investigationId, 'breach', email, 'Have I Been Pwned', {
    status: 'FOUND',
    confidence: 100,
    source_url: breach.Domain ? `https://${breach.Domain}` : 'https://haveibeenpwned.com/',
    verification_status: breach.IsVerified ? 'Confirmed by provider' : 'Reported by source',
    first_seen: breach.BreachDate || null,
    last_seen: breach.BreachDate || null,
    metadata: {
      breach_name: breach.Name,
      organisation: breach.Title,
      breach_date: breach.BreachDate || null,
      published_date: breach.AddedDate || null,
      modified_date: breach.ModifiedDate || null,
      data_classes: breach.DataClasses || [],
      is_verified: !!breach.IsVerified,
      is_sensitive: !!breach.IsSensitive,
    },
  }));
}

async function dnsEmail(email, investigationId) {
  const domain = email.split('@')[1];
  if (!domain) return [];
  try {
    const [mx, spf, dmarc] = await Promise.all([
      safeJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`),
      safeJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`),
      safeJson(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`),
    ]);
    const txt = [...(spf.Answer || []), ...(dmarc.Answer || [])].map((answer) => answer.data).filter(Boolean);
    return [providerResult(investigationId, 'domain', email, 'DNS-over-HTTPS', {
      status: mx.Answer?.length ? 'FOUND' : 'NOT_FOUND',
      confidence: mx.Answer?.length ? 100 : 60,
      source_url: `https://dns.google/query?name=${encodeURIComponent(domain)}&rr_type=MX`,
      metadata: {
        domain,
        mx: mx.Answer?.map((answer) => answer.data).filter(Boolean) || [],
        txt_records: txt,
        has_spf: txt.some((record) => /spf1/i.test(record)),
        has_dmarc: txt.some((record) => /v=dmarc1/i.test(record)),
      },
    })];
  } catch (error) {
    return [providerError(investigationId, 'domain', email, 'DNS-over-HTTPS', error)];
  }

  async function gravatarEmail(email, investigationId) {
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(email.trim().toLowerCase())))]
      .map((byte) => byte.toString(16).padStart(2, '0')).join('');
    const cacheKey = `gravatar:${hash}`;
    let profile = cacheGet(cacheKey);
    if (!profile) {
      try {
        profile = await safeJson(`https://en.gravatar.com/${hash}.json`);
        cacheSet(cacheKey, profile, 6 * 60 * 60 * 1000);
      } catch (error) {
        if (error.status === 404) return [providerResult(investigationId, 'social_account', email, 'Gravatar', {
          platform: 'Gravatar',
          status: 'NOT_FOUND',
          confidence: 100,
          source_url: `https://gravatar.com/${hash}`,
        })];
        return [providerError(investigationId, 'social_account', email, 'Gravatar', error)];
      }
    }
    const entry = Array.isArray(profile.entry) ? profile.entry[0] : null;
    if (!entry) return [providerResult(investigationId, 'social_account', email, 'Gravatar', {
      platform: 'Gravatar',
      status: 'NOT_FOUND',
      confidence: 100,
      source_url: `https://gravatar.com/${hash}`,
    })];
    const account = entry.accounts?.[0] || {};
    return [providerResult(investigationId, 'social_account', email, 'Gravatar', {
      platform: 'Gravatar',
      display_name: entry.displayName || entry.name?.formatted || null,
      profile_url: entry.profileUrl || account.url || `https://gravatar.com/${hash}`,
      source_url: entry.profileUrl || account.url || `https://gravatar.com/${hash}`,
      status: 'FOUND',
      confidence: 80,
      metadata: {
        avatar_url: entry.thumbnailUrl || null,
        location: entry.currentLocation || null,
        biography: entry.aboutMe || null,
        accounts: entry.accounts || [],
      },
    })];
  }

  async function rdapDomain(email, investigationId) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return [];
    const cacheKey = `rdap:${domain}`;
    let rdap = cacheGet(cacheKey);
    try {
      if (!rdap) {
        rdap = await safeJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
        cacheSet(cacheKey, rdap, 24 * 60 * 60 * 1000);
      }
    } catch (error) {
      if (error.status === 404) return [providerResult(investigationId, 'domain', email, 'RDAP', {
        status: 'NOT_FOUND',
        confidence: 90,
        source_url: `https://rdap.org/domain/${encodeURIComponent(domain)}`,
        metadata: { domain },
      })];
      return [providerError(investigationId, 'domain', email, 'RDAP', error)];
    }
    const registration = rdap.events?.find((event) => event.eventAction === 'registration');
    const nameservers = rdap.nameservers?.map((server) => server.ldhName).filter(Boolean) || [];
    return [providerResult(investigationId, 'domain', email, 'RDAP', {
      platform: 'Domain registration',
      status: 'FOUND',
      confidence: 95,
      source_url: `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      first_seen: registration?.eventDate || null,
      metadata: {
        domain,
        registrar: rdap.entities?.find((entity) => entity.roles?.includes('registrar'))?.vcardArray?.[1]?.find((item) => item[0] === 'fn')?.[3] || null,
        nameservers,
        status: rdap.status || [],
      },
    })];
  }

  async function certificateRecords(email, investigationId) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return [];
    const cacheKey = `crt:${domain}`;
    let records = cacheGet(cacheKey);
    try {
      if (!records) {
        records = await safeJson(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`);
        cacheSet(cacheKey, records, 24 * 60 * 60 * 1000);
      }
    } catch (error) {
      return [providerError(investigationId, 'domain', email, 'Certificate Transparency', error)];
    }
    const uniqueNames = [...new Set((Array.isArray(records) ? records : [])
      .flatMap((record) => String(record.name_value || '').split('\n'))
      .map((name) => name.trim().toLowerCase())
      .filter((name) => name && (name === domain || name.endsWith(`.${domain}`))))].slice(0, 100);
    if (!uniqueNames.length) return [providerResult(investigationId, 'domain', email, 'Certificate Transparency', {
      status: 'NOT_FOUND',
      confidence: 70,
      source_url: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`,
      metadata: { domain },
    })];
    return [providerResult(investigationId, 'domain', email, 'Certificate Transparency', {
      status: 'FOUND',
      confidence: 85,
      source_url: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`,
      metadata: { domain, certificate_names: uniqueNames, unique_name_count: uniqueNames.length },
    })];
  }

  async function waybackDomain(email, investigationId) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return [];
    const cacheKey = `wayback:${domain}`;
    let rows = cacheGet(cacheKey);
    try {
      if (!rows) {
        const response = await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`*.${domain}/*`)}&output=json&filter=statuscode:200&filter=mimetype:text/html&limit=20&collapse=urlkey`, {
          headers: { 'user-agent': 'Ransom-Intel-Search' },
          signal: AbortSignal.timeout(12000),
        });
        if (!response.ok) throw Object.assign(new Error(`Provider HTTP ${response.status}`), { status: response.status });
        rows = await response.json();
        cacheSet(cacheKey, rows, 24 * 60 * 60 * 1000);
      }
    } catch (error) {
      return [providerError(investigationId, 'archive', email, 'Internet Archive', error)];
    }
    if (!Array.isArray(rows) || rows.length < 2) return [providerResult(investigationId, 'archive', email, 'Internet Archive', {
      status: 'NOT_FOUND',
      confidence: 60,
      source_url: `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`*.${domain}/*`)}`,
      metadata: { domain },
    })];
    const [, ...captures] = rows;
    const urls = [...new Set(captures.map((capture) => capture[2]).filter(Boolean))].slice(0, 20);
    const timestamps = captures.map((capture) => capture[1]).filter(Boolean).sort();
    return [providerResult(investigationId, 'archive', email, 'Internet Archive', {
      status: 'FOUND',
      confidence: 70,
      source_url: `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`*.${domain}/*`)}`,
      first_seen: timestamps.length ? `${timestamps[0].slice(0, 4)}-${timestamps[0].slice(4, 6)}-${timestamps[0].slice(6, 8)}` : null,
      last_seen: timestamps.length ? `${timestamps.at(-1).slice(0, 4)}-${timestamps.at(-1).slice(4, 6)}-${timestamps.at(-1).slice(6, 8)}` : null,
      metadata: { domain, captured_urls: urls, capture_count: captures.length },
    })];
  }
}

async function githubUsername(username, investigationId, env) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'Ransom-Intel-Search' };
  if (env.GITHUB_API_TOKEN) headers.authorization = `Bearer ${env.GITHUB_API_TOKEN}`;
  const key = `github:${username.toLowerCase()}`;
  let user = cacheGet(key);
  try {
    if (!user) {
      user = await safeJson(`https://api.github.com/users/${encodeURIComponent(username)}`, { headers });
      cacheSet(key, user, 6 * 60 * 60 * 1000);
    }
  } catch (error) {
    if (error.status === 404) return [providerResult(investigationId, 'social_account', username, 'GitHub', { platform: 'GitHub', status: 'NOT_FOUND', confidence: 100 })];
    return [providerError(investigationId, 'social_account', username, 'GitHub', error)];
  }
  return [providerResult(investigationId, 'social_account', username, 'GitHub', {
    platform: 'GitHub',
    display_name: user.name || user.login,
    profile_url: user.html_url,
    source_url: user.html_url,
    status: 'FOUND',
    confidence: 100,
    first_seen: user.created_at || null,
    metadata: { biography: user.bio || null, avatar_url: user.avatar_url || null, public_repos: user.public_repos, location: user.location || null, email: user.email || null },
  })];
}

async function dispatchMaigret(username, investigationId, env) {
  if (!env.GITHUB_DISPATCH_TOKEN || !env.MAIGRET_REPOSITORY) {
    return providerResult(investigationId, 'social_account', username, 'Maigret', { platform: 'Maigret', status: 'DISABLED', confidence: 0, metadata: { reason: 'GITHUB_DISPATCH_TOKEN or MAIGRET_REPOSITORY is not configured' } });
  }
  const response = await fetch(`https://api.github.com/repos/${env.MAIGRET_REPOSITORY}/dispatches`, {
    method: 'POST',
    headers: { authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`, accept: 'application/vnd.github+json', 'user-agent': 'Ransom-Intel-Search', 'content-type': 'application/json' },
    body: JSON.stringify({ event_type: 'maigret-investigation', client_payload: { investigation_id: investigationId, username } }),
    signal: AbortSignal.timeout(12000),
  });
  if (!response.ok) return providerResult(investigationId, 'social_account', username, 'Maigret', { status: 'ERROR', confidence: 0, metadata: { reason: `GitHub dispatch failed with HTTP ${response.status}` } });
  return providerResult(investigationId, 'social_account', username, 'Maigret', { status: 'UNKNOWN', confidence: 0, metadata: { job_state: 'Pending in GitHub Actions' } });
}

async function hudsonRockEmail(email, investigationId, env) {
  if (!env.HUDSON_ROCK_API_URL || !env.HUDSON_ROCK_API_KEY) return providerResult(investigationId, 'exposure', email, 'Infostealer provider', { status: 'DISABLED', confidence: 0, metadata: { reason: 'No authorised infostealer provider is configured' } });
  try {
    const data = await safeJson(env.HUDSON_ROCK_API_URL, { method: 'POST', headers: { authorization: `Bearer ${env.HUDSON_ROCK_API_KEY}`, 'content-type': 'application/json' }, body: JSON.stringify({ email }) });
    const observations = Array.isArray(data.observations) ? data.observations : [];
    return observations.map((item) => providerResult(investigationId, 'exposure', email, item.provider || 'Infostealer provider', {
      status: 'FOUND', confidence: Number(item.confidence) || 50, source_url: item.source_url || null,
      first_seen: item.first_observed || null, last_seen: item.last_observed || null,
      metadata: { associated_domain: item.domain || email.split('@')[1] || null, source_reference: item.source_reference || null, collection_date: iso(), prohibited_data_excluded: true },
    }));
  } catch (error) {
    return providerError(investigationId, 'exposure', email, 'Infostealer provider', error);
  }
}

function buildDerived(investigation) {
  const timeline = [];
  for (const finding of investigation.results) {
    const metadata = finding.metadata || {};
    if (finding.type === 'breach') {
      if (metadata.breach_date) timeline.push({ id: randomId(), type: 'breach_occurrence', date: metadata.breach_date, date_type: 'occurrence', finding_id: finding.id, source: finding.source, label: `${metadata.breach_name || 'Breach'} occurred` });
      if (metadata.published_date) timeline.push({ id: randomId(), type: 'breach_publication', date: metadata.published_date, date_type: 'publication', finding_id: finding.id, source: finding.source, label: `${metadata.breach_name || 'Breach'} published` });
    }
    if (finding.first_seen) timeline.push({ id: randomId(), type: finding.type === 'social_account' ? 'account_creation' : 'first_observation', date: finding.first_seen, date_type: 'provider_observation', finding_id: finding.id, source: finding.source, label: `${finding.type === 'social_account' ? 'Account observed' : 'First observation'}: ${finding.identifier}` });
    if (finding.last_seen && finding.last_seen !== finding.first_seen) timeline.push({ id: randomId(), type: 'last_observation', date: finding.last_seen, date_type: 'provider_observation', finding_id: finding.id, source: finding.source, label: `Last observation: ${finding.identifier}` });
  }
  timeline.sort((a, b) => (a.date || '').localeCompare(b.date || ''));

  const nodes = [];
  const edges = [];
  const node = (id, type, label) => { if (!nodes.some((n) => n.id === id)) nodes.push({ id, type, label }); };
  for (const identifier of investigation.identifiers) node(`${identifier.type}:${identifier.value}`, identifier.type, identifier.value);
  for (const finding of investigation.results) {
    if (finding.type === 'social_account' && finding.status === 'FOUND') {
      const accountId = `account:${finding.profile_url || `${finding.platform}:${finding.identifier}`}`;
      node(accountId, 'account', finding.display_name || `${finding.platform}/${finding.identifier}`);
      edges.push({ source: `${finding.identifier.includes('@') ? 'email' : 'username'}:${finding.identifier}`, target: accountId, type: 'public_profile', evidence: finding.source_url || finding.source, confidence: finding.confidence, explanation: 'Public profile discovered by an authorised provider; identity is not automatically confirmed.' });
    }
    if (finding.type === 'breach') {
      const breachId = `breach:${finding.metadata.breach_name || finding.identifier}`;
      node(breachId, 'breach', finding.metadata.breach_name || 'Breach');
      edges.push({ source: `email:${finding.identifier}`, target: breachId, type: 'breach_exposure', evidence: finding.source_url || finding.source, confidence: finding.confidence, explanation: finding.verification_status || 'Breach exposure reported by provider.' });
    }
    if (finding.type === 'exposure' && finding.status === 'FOUND') {
      const exposureId = `exposure:${finding.source}:${finding.identifier}`;
      node(exposureId, 'exposure', finding.source);
      edges.push({ source: `email:${finding.identifier}`, target: exposureId, type: 'infostealer_exposure', evidence: finding.source_url || finding.source, confidence: finding.confidence, explanation: 'Authorised infostealer metadata association; raw credentials were excluded.' });
    }
  }
  return { timeline, nodes, edges };
}

function recalculate(investigation) {
  const jobs = investigation.provider_jobs;
  const unfinished = jobs.filter((job) => ['pending', 'running'].includes(job.status)).length;
  const errors = jobs.filter((job) => ['failed', 'error'].includes(job.status)).length;
  investigation.status = unfinished ? (jobs.some((job) => job.status === 'completed') ? 'partial' : 'running') : errors ? 'partial' : 'completed';
  if (jobs.every((job) => job.status === 'cancelled')) investigation.status = 'cancelled';
  const derived = buildDerived(investigation);
  investigation.timeline = derived.timeline;
  investigation.graph = { nodes: derived.nodes, edges: derived.edges };
  investigation.updated_at = iso();
  investigation.summary = {
    identifier_count: investigation.identifiers.length,
    total_providers: jobs.length,
    successful_providers: jobs.filter((job) => job.status === 'completed').length,
    failed_providers: jobs.filter((job) => ['failed', 'error'].includes(job.status)).length,
    total_findings: investigation.results.filter((finding) => finding.status === 'FOUND').length,
  };
}

async function runInvestigation(investigation, env) {
  const providers = investigation.providers;
  const identifiers = investigation.identifiers;
  const jobs = [];
  for (const identifier of identifiers) {
    if (identifier.type === 'email') {
      if (providers.includes('hibp')) jobs.push({ provider: 'Have I Been Pwned account search', status: 'running', started_at: iso() });
      if (providers.includes('breach_catalog')) jobs.push({ provider: 'Public breach catalogue', status: 'running', started_at: iso() });
      if (providers.includes('pwned_passwords') && investigation.password_hash_prefix && investigation.password_hash_suffix) jobs.push({ provider: 'HIBP Pwned Passwords', status: 'running', started_at: iso() });
      if (providers.includes('dns')) jobs.push({ provider: 'DNS-over-HTTPS', status: 'running', started_at: iso() });
      if (providers.includes('gravatar')) jobs.push({ provider: 'Gravatar', status: 'running', started_at: iso() });
      if (providers.includes('rdap')) jobs.push({ provider: 'RDAP', status: 'running', started_at: iso() });
      if (providers.includes('certificate')) jobs.push({ provider: 'Certificate Transparency', status: 'running', started_at: iso() });
      if (providers.includes('wayback')) jobs.push({ provider: 'Internet Archive', status: 'running', started_at: iso() });
      if (providers.includes('github')) jobs.push({ provider: 'GitHub', status: 'running', started_at: iso() });
      if (providers.includes('infostealer')) jobs.push({ provider: 'Infostealer provider', status: 'running', started_at: iso() });
    } else if (identifier.type === 'username') {
      if (providers.includes('github')) jobs.push({ provider: 'GitHub', status: 'running', started_at: iso() });
      if (providers.includes('maigret')) jobs.push({ provider: 'Maigret', status: 'pending', started_at: iso() });
    }
  }
  investigation.provider_jobs = jobs;
  investigation.status = jobs.length ? 'running' : 'failed';
  recalculate(investigation);

  const runProvider = async (providerName, work) => {
    const job = jobs.find((item) => item.provider === providerName && item.status === 'running');
    try {
      const result = await work();
      const rows = Array.isArray(result) ? result : [result];
      investigation.results.push(...rows);
      if (job) job.status = 'completed';
      if (job) job.completed_at = iso();
    } catch (error) {
      if (job) { job.status = 'failed'; job.completed_at = iso(); job.error = 'Provider request failed'; }
    }
  };

  await Promise.all(identifiers.flatMap((identifier) => {
    const calls = [];
    if (identifier.type === 'email') {
      if (providers.includes('hibp')) calls.push(runProvider('Have I Been Pwned account search', () => hibpEmail(identifier.value, investigation.id, env)));
      if (providers.includes('breach_catalog')) calls.push(runProvider('Public breach catalogue', () => publicBreachCatalog(identifier.value, investigation.id)));
      if (providers.includes('pwned_passwords') && investigation.password_hash_prefix && investigation.password_hash_suffix) calls.push(runProvider('HIBP Pwned Passwords', () => pwnedPasswords(investigation.password_hash_prefix, investigation.password_hash_suffix, investigation.id, identifier.value)));
      if (providers.includes('dns')) calls.push(runProvider('DNS-over-HTTPS', () => dnsEmail(identifier.value, investigation.id)));
      if (providers.includes('gravatar')) calls.push(runProvider('Gravatar', () => gravatarEmail(identifier.value, investigation.id)));
      if (providers.includes('rdap')) calls.push(runProvider('RDAP', () => rdapDomain(identifier.value, investigation.id)));
      if (providers.includes('certificate')) calls.push(runProvider('Certificate Transparency', () => certificateRecords(identifier.value, investigation.id)));
      if (providers.includes('wayback')) calls.push(runProvider('Internet Archive', () => waybackDomain(identifier.value, investigation.id)));
      if (providers.includes('infostealer')) calls.push(runProvider('Infostealer provider', () => hudsonRockEmail(identifier.value, investigation.id, env)));
      if (providers.includes('github')) calls.push(runProvider('GitHub', () => githubUsername(identifier.value.split('@')[0], investigation.id, env)));
    } else {
      if (providers.includes('github')) calls.push(runProvider('GitHub', () => githubUsername(identifier.value, investigation.id, env)));
      if (providers.includes('maigret')) calls.push((async () => {
        const job = jobs.find((item) => item.provider === 'Maigret');
        const result = await dispatchMaigret(identifier.value, investigation.id, env);
        investigation.results.push(result);
        if (job) { job.status = result.status === 'DISABLED' || result.status === 'ERROR' ? 'completed' : 'pending'; job.completed_at = result.status === 'UNKNOWN' ? null : iso(); }
      })());
    }
    return calls;
  }));
  recalculate(investigation);
}

export async function handleOsint(request, env, url, origin, json) {
  const pathname = url.pathname;
  const method = request.method;
  const authRequired = env.OSINT_API_TOKEN;
  if (authRequired && request.headers.get('Authorization') !== `Bearer ${authRequired}`) return json({ error: 'OSINT investigation authentication required' }, 401, origin, env);

  if (pathname === '/api/osint/providers' && method === 'GET') return json({
    providers: [
      { name: 'HIBP Pwned Passwords', category: 'Password range exposure', enabled: true, configured: true, status: 'available', cost: '$0', method: 'K-anonymity SHA-1 range' },
      { name: 'Public breach catalogue', category: 'Breach metadata', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Public catalog metadata' },
      { name: 'Have I Been Pwned account search', category: 'Breach intelligence', enabled: !!env.HIBP_API_KEY, configured: !!env.HIBP_API_KEY, status: env.HIBP_API_KEY ? 'available' : 'requires_key', cost: env.HIBP_API_KEY === '00000000000000000000000000000000' ? '$0 test key; test accounts only' : 'Paid API subscription', method: 'HIBP API v3' },
      { name: 'GitHub', category: 'Public profile', enabled: true, configured: true, status: 'available', cost: '$0 public tier', method: 'Public API' },
      { name: 'DNS-over-HTTPS', category: 'Email domain', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Google DNS JSON' },
      { name: 'Gravatar', category: 'Email profile', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Public profile JSON' },
      { name: 'RDAP', category: 'Domain registration', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Public RDAP registry' },
      { name: 'Certificate Transparency', category: 'Domain infrastructure', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Public crt.sh records' },
      { name: 'Internet Archive', category: 'Historical observations', enabled: true, configured: true, status: 'available', cost: '$0', method: 'Public CDX API' },
      { name: 'Maigret', category: 'Username enumeration', enabled: !!env.GITHUB_DISPATCH_TOKEN && !!env.MAIGRET_REPOSITORY, configured: !!env.GITHUB_DISPATCH_TOKEN && !!env.MAIGRET_REPOSITORY, status: env.GITHUB_DISPATCH_TOKEN && env.MAIGRET_REPOSITORY ? 'available' : 'disabled', cost: '$0 within GitHub Actions limits', method: 'GitHub Actions + Python' },
      { name: 'Infostealer provider', category: 'Exposure metadata', enabled: !!env.HUDSON_ROCK_API_URL && !!env.HUDSON_ROCK_API_KEY, configured: !!env.HUDSON_ROCK_API_URL && !!env.HUDSON_ROCK_API_KEY, status: env.HUDSON_ROCK_API_URL && env.HUDSON_ROCK_API_KEY ? 'available' : 'requires_paid_subscription', cost: 'Optional paid/licensed', method: 'Authorised metadata API' },
    ],
  }, 200, origin, env);

  if (pathname === '/api/osint/investigations' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, origin, env); }
    const rawIdentifiers = Array.isArray(body.identifiers) ? body.identifiers : [body.email, body.username].filter(Boolean);
    const identifiers = [];
    for (const raw of rawIdentifiers) {
      const identifier = normalizeIdentifier(raw);
      if (identifier && !identifiers.some((item) => item.type === identifier.type && item.value === identifier.value)) identifiers.push(identifier);
    }
    if (!identifiers.length) return json({ error: 'Provide at least one valid email address or username' }, 400, origin, env);
    if (identifiers.length > 100) return json({ error: 'Bulk investigations support at most 100 identifiers' }, 400, origin, env);
    const available = ['hibp', 'dns', 'github', 'maigret', 'infostealer', 'breach_catalog', 'pwned_passwords', 'gravatar', 'rdap', 'certificate', 'wayback'];
    const providers = Array.isArray(body.providers)
      ? [...new Set(body.providers.filter((provider) => available.includes(provider)))]
      : ['dns', 'github', 'breach_catalog', 'gravatar', 'rdap', 'certificate', 'wayback'];
    const investigation = {
      id: randomId(),
      mode: ['standard', 'extended', 'bulk'].includes(body.mode) ? body.mode : 'standard',
      status: 'pending',
      identifiers,
      providers,
      provider_jobs: [],
      results: [],
      timeline: [],
      graph: { nodes: [], edges: [] },
      evidence: [],
      created_at: iso(),
      updated_at: iso(),
      summary: {},
      password_hash_prefix: /^[A-F0-9]{5}$/.test(body.password_hash_prefix || '') ? body.password_hash_prefix : null,
      password_hash_suffix: /^[A-F0-9]{35}$/.test(body.password_hash_suffix || '') ? body.password_hash_suffix : null,
    };
    investigations.set(investigation.id, investigation);
    await runInvestigation(investigation, env);
    return json(investigation, 201, origin, env);
  }

  if (pathname === '/api/osint/investigations' && method === 'GET') {
    const rows = [...investigations.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
    return json({ investigations: rows }, 200, origin, env);
  }

  const match = pathname.match(/^\/api\/osint\/investigations\/([^/]+)(?:\/(status|accounts|breaches|exposures|timeline|graph|evidence|export))?$/);
  if (match) {
    const investigation = investigations.get(match[1]);
    if (!investigation) return json({ error: 'Investigation not found' }, 404, origin, env);
    const view = match[2];
    if (method === 'DELETE') { investigations.delete(investigation.id); return json({ deleted: true }, 200, origin, env); }
    if (method === 'GET') {
      if (!view) return json(investigation, 200, origin, env);
      if (view === 'status') return json({ id: investigation.id, status: investigation.status, provider_jobs: investigation.provider_jobs, summary: investigation.summary, updated_at: investigation.updated_at }, 200, origin, env);
      if (view === 'accounts') return json({ accounts: investigation.results.filter((result) => result.type === 'social_account') }, 200, origin, env);
      if (view === 'breaches') return json({ breaches: investigation.results.filter((result) => result.type === 'breach') }, 200, origin, env);
      if (view === 'exposures') return json({ exposures: investigation.results.filter((result) => result.type === 'exposure') }, 200, origin, env);
      if (view === 'timeline') return json({ timeline: investigation.timeline }, 200, origin, env);
      if (view === 'graph') return json(investigation.graph, 200, origin, env);
      if (view === 'evidence') return json({ evidence: investigation.results.map((result) => ({ finding_id: result.id, source: result.source, source_url: result.source_url, collected_at: result.collected_at, confidence: result.confidence, metadata: result.metadata })) }, 200, origin, env);
    }
    if (method === 'POST' && view === 'export') return json(investigation, 200, origin, env);
  }

  if (pathname === '/api/osint/maigret/callback' && method === 'POST') {
    if (!env.MAIGRET_CALLBACK_SECRET || request.headers.get('Authorization') !== `Bearer ${env.MAIGRET_CALLBACK_SECRET}`) return json({ error: 'Invalid Maigret callback authentication' }, 401, origin, env);
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, origin, env); }
    const investigation = investigations.get(body.investigation_id);
    if (!investigation) return json({ error: 'Investigation not found' }, 404, origin, env);
    for (const row of Array.isArray(body.results) ? body.results : []) {
      investigation.results.push(providerResult(investigation.id, 'social_account', body.username, 'Maigret', {
        platform: row.platform, display_name: row.display_name || null, profile_url: row.profile_url || null, source_url: row.source_url || row.profile_url || null,
        status: row.status || 'FOUND', confidence: Number(row.confidence) || 70, first_seen: row.first_seen || null, last_seen: row.last_seen || null, metadata: row.metadata || {},
      }));
    }
    const job = investigation.provider_jobs.find((item) => item.provider === 'Maigret');
    if (job) { job.status = 'completed'; job.completed_at = iso(); }
    recalculate(investigation);
    return json({ accepted: true }, 200, origin, env);
  }

  return null;
}
