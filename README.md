# Ransom Intel

Static GitHub Pages frontend with a small Cloudflare Worker API proxy. The browser calls only the Worker; the Worker queries RansomLook, RansomFeed, and Ransomware.live Pro concurrently. The Pro key is stored as an encrypted Worker secret and is never sent to the frontend.

Live portal: https://imyan16.github.io/ransom-intel-search/  
Worker health: https://ransom-intel-api.yanthegreat99.workers.dev/api/health

## Why the Worker is needed

Live checks on 20 Nov 2026 found the upstream APIs did not return the CORS headers required by GitHub Pages. The Worker makes server-side requests to those APIs and returns data to the Pages origin with a controlled CORS policy. This is the only backend component; there is no database, ingestion job, or scheduled polling.

## Source adapters

- **RansomLook:** `GET https://www.ransomlook.io/api/search?query=…`; falls back to observed `q` parameter if the documented parameter is rejected. Maps post title, group, discovery timestamp, optional description, link, and screenshot. Discovery is not an attack date.
- **RansomFeed:** `GET https://api.ransomfeed.it/search/{term}/offset/1000`. If that API returns no matches, the Worker checks RansomFeed’s public site-search endpoint for newer posts that have not reached the documented API yet. Search includes victim, description, city, region, and sector. The documented API rate limit is 5 requests/minute per IP.
- **Ransomware.live Pro:** `GET https://api-pro.ransomware.live/victims/search?q=…`, authenticated with `X-API-KEY` from the Worker secret binding.

Missing fields stay null and render as “Not Available”. Attack, discovery, publication, and update dates remain separate. A ransomware group’s post is an unverified claim, not confirmed proof of breach. Source raw responses are retained per record for traceability.

## Features

- Concurrent independent source searches and per-source status/errors.
- Exact victim-name option, normalized records, conservative cross-source matching, and preserved source-specific records.
- Country, industry, group, source, date, match status, evidence, and website filters.
- Victim detail dialog, source links, screenshot previews, copyable website/domain, pagination, and CSV/JSON exports.
- Five-minute browser cache per source/query, force refresh, and cache clearing.
- Worker in-memory cache and per-client request limit; upstream API rate limits still apply.
- No browser-held API key and no permanent search history.

## Deploy the free Worker

Cloudflare Workers Free includes a daily request allowance; see the current [Workers pricing and limits](https://developers.cloudflare.com/workers/platform/pricing/). RansomFeed’s upstream five-per-minute limit can be the tighter constraint.

1. Install Node.js 20+ and authenticate Wrangler: `npx wrangler login`.
2. Edit `worker/wrangler.toml` and set `ALLOWED_ORIGINS` to your exact GitHub Pages origin, for example `https://yourname.github.io`. Include `http://localhost:8080` only if you use local development. CORS is not authentication, so keep the allowlist narrow.
3. From the repository root, add your Pro API key as a secret: `npx wrangler secret put RANSOMWARE_LIVE_API_KEY --config worker/wrangler.toml`.
4. Deploy: `npx wrangler deploy --config worker/wrangler.toml`. Copy the resulting `workers.dev` URL.
5. Put that URL in `src/config.js` as `window.RI_CONFIG.apiBase`, then push the change. The URL is public; it contains no credential.

The Worker has a 60-request/minute per-client guard, 12-second upstream timeouts, one retry for transient failures, and a five-minute in-memory success cache. Provider rate limits remain in force. The Pro secret is configured in Cloudflare and must never be added to `src/config.js` or GitHub Pages.

## Deploy GitHub Pages

In repository Settings → Pages, select **GitHub Actions**. Pushing to `main` runs the tests, builds the static site into `dist/`, and deploys it. The Worker is deployed separately using Wrangler; no GitHub credential is needed for that manual deployment path.

For local frontend work, set the Worker origin in `src/config.js`, allow `http://localhost:8080` in `ALLOWED_ORIGINS`, then run `npm run serve` and open `http://localhost:8080`.

## Tests and build

Run `npm test` for browser-to-Worker adapter routing, Worker CORS policy, Pro secret handling, upstream parsing, source failure isolation, matching, cache behavior, and exports. Fixtures are test-only. Run `npm run build` to create the Pages artifact.

## References

- [RansomLook API docs](https://www.ransomlook.io/doc/#/StatsAPI/get_search_endpoint)
- [RansomFeed API docs](https://ransomfeed.it/docs/#api-html)
- [Ransomware.live Pro API docs](https://api-pro.ransomware.live/docs)
- [Cloudflare Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

## OSINT Investigation

The static frontend includes a separate OSINT workspace for email addresses and usernames. It calls only the same Cloudflare Worker origin. Investigation history is temporary in Worker memory and is reset by a Worker restart or deployment.

### OSINT provider configuration

Configure provider credentials with `npx wrangler secret put <NAME> --config worker/wrangler.toml`.

- `HIBP_API_KEY` — Have I Been Pwned API v3 key. Required for real breach searches.
- `GITHUB_API_TOKEN` — optional GitHub API token for public profile lookups and higher limits.
- `GITHUB_DISPATCH_TOKEN` — GitHub fine-grained token with repository Actions write permission for Maigret dispatches.
- `MAIGRET_REPOSITORY` — repository in `owner/repository` format that contains `.github/workflows/maigret.yml`.
- `MAIGRET_CALLBACK_SECRET` — optional secret for the secured Maigret callback endpoint.
- `MAIGRET_CALLBACK_URL` — reserved callback configuration; callback authentication is not forwarded as a workflow secret in the dispatch payload.
- `HUDSON_ROCK_API_URL` — optional authorised infostealer metadata API URL.
- `HUDSON_ROCK_API_KEY` — optional authorised infostealer metadata API key.
- `OSINT_API_TOKEN` — optional bearer token that protects OSINT investigation endpoints. When set, browser clients must provide it; this is not recommended for public static GitHub Pages unless the same secret is intentionally exposed through a different private client.

For Maigret, the Worker dispatches `maigret-investigation` through GitHub Actions. The workflow uses the Python package in a hosted runner and uploads private JSON/artifact output for seven days. Because public callback delivery can be credential-expensive and unsafe, the callback endpoint exists for an authorized private integration and the artifact workflow is the documented default alternative. Never put GitHub or provider tokens in `src/config.js` or HTML.

The infostealer module has no synthetic data fallback. It remains unavailable until an authorised API URL and key are configured. Only metadata is accepted; no password, cookie, session token, or raw log fields are displayed or cached.

### OSINT API namespace

- `POST /api/osint/investigations`
- `GET /api/osint/investigations`
- `GET /api/osint/investigations/:id`
- `GET /api/osint/investigations/:id/status`
- `GET /api/osint/investigations/:id/accounts`
- `GET /api/osint/investigations/:id/breaches`
- `GET /api/osint/investigations/:id/exposures`
- `GET /api/osint/investigations/:id/timeline`
- `GET /api/osint/investigations/:id/graph`
- `GET /api/osint/investigations/:id/evidence`
- `POST /api/osint/investigations/:id/export`
- `DELETE /api/osint/investigations/:id`
- `GET /api/osint/providers`
- `POST /api/osint/maigret/callback`

All provider cache and investigation storage is separate from the ransomware source cache. The Worker currently uses temporary in-memory storage and does not require D1. Persistent history requires a future D1 binding.
