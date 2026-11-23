import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import {isValidEmail, normalizeUsername} from '../worker/src/osint.js';

const env = {
  ALLOWED_ORIGINS: 'https://analyst.github.io',
  HIBP_API_KEY: '00000000000000000000000000000000',
  GITHUB_API_TOKEN: 'github-test-secret',
};
const request = (path, method = 'GET', body, origin = 'https://analyst.github.io') => new Request(`https://worker.test${path}`, {
  method,
  headers: { Origin: origin, 'content-type': 'application/json', 'CF-Connecting-IP': '192.0.2.44', ...(body ? {} : {}) },
  body: body ? JSON.stringify(body) : undefined,
});

test('validates and normalises email and username identifiers', () => {
  assert.equal(isValidEmail('Analyst@Example.COM'), true);
  assert.equal(isValidEmail('not-an-email'), false);
  assert.equal(normalizeUsername('@example_user'), 'example_user');
  assert.equal(normalizeUsername('bad user'), null);
});

test('Pwned Passwords range check never receives a plaintext password', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const parsed = new URL(url);
    assert.equal(parsed.hostname, 'api.pwnedpasswords.com');
    assert.equal(parsed.pathname, '/range/00000');
    return new Response('00000000000000000000000000000000000:4\n', { status: 200 });
  };
  try {
    const response = await worker.fetch(request('/api/osint/investigations', 'POST', {
      identifiers: ['analyst@example.com'],
      providers: ['pwned_passwords'],
      password_hash_prefix: '00000',
      password_hash_suffix: '00000000000000000000000000000000000',
    }), env);
    const data = await response.json();
    assert.equal(response.status, 201);
    assert.ok(data.results.some((finding) => finding.source === 'HIBP Pwned Passwords'), JSON.stringify(data));
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('OSINT provider endpoint does not expose secret values', async () => {
  const response = await worker.fetch(request('/api/osint/providers'), env);
  const data = await response.json();
  assert.equal(response.status, 200);
  assert.equal(JSON.stringify(data).includes('00000000000000000000000000000000'), false);
  assert.ok(data.providers.some((provider) => provider.name === 'HIBP Pwned Passwords'));
  assert.ok(data.providers.some((provider) => provider.name === 'Have I Been Pwned account search'));
  assert.ok(data.providers.some((provider) => provider.status === 'available'));
});

test('OSINT investigation normalises identifiers and handles provider mocks independently', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const parsed = new URL(url);
    if (parsed.hostname === 'dns.google') return new Response(JSON.stringify({ Answer: [{ data: '10 mail.example.com.' }] }), { status: 200 });
    if (parsed.hostname === 'api.github.com') return new Response(JSON.stringify({ status: '404' }), { status: 404 });
    if (parsed.hostname === 'haveibeenpwned.com') return new Response(JSON.stringify([{
      Name: 'ExampleBreach', Title: 'Example Org', Domain: 'example.org', BreachDate: '2024-01-02',
      AddedDate: '2024-02-03', IsVerified: true, DataClasses: ['Email addresses'],
    }]), { status: 200 });
    throw new Error(`Unexpected mock URL ${url}`);
  };
  try {
    const response = await worker.fetch(request('/api/osint/investigations', 'POST', {
      identifiers: [' Analyst@Example.com ', 'analyst', 'analyst'],
      providers: ['hibp', 'dns', 'github'],
      mode: 'extended',
    }), env);
    const data = await response.json();
    assert.equal(response.status, 201);
    assert.equal(data.identifiers.length, 2);
    assert.equal(data.status === 'completed' || data.status === 'partial', true);
    assert.ok(data.results.some((finding) => finding.type === 'breach'));
    assert.ok(data.timeline.some((event) => event.date_type === 'occurrence'));
    assert.ok(data.graph.edges.some((edge) => edge.type === 'breach_exposure'));
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('Maigret dispatch can remain pending and is never marked complete too early', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('', { status: 200 });
  try {
    const response = await worker.fetch(request('/api/osint/investigations', 'POST', {
      identifiers: ['sample_username'],
      providers: ['maigret'],
    }), {
      ALLOWED_ORIGINS: env.ALLOWED_ORIGINS,
      GITHUB_DISPATCH_TOKEN: 'dispatch-test-secret',
      MAIGRET_REPOSITORY: 'owner/repository',
    });
    const data = await response.json();
    assert.equal(response.status, 201);
    assert.equal(data.status, 'running');
    assert.equal(data.provider_jobs[0].status, 'pending');
  } finally {
    globalThis.fetch = oldFetch;
  }
});
