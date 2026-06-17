# VibeCheck

VibeCheck is a 60-second, read-only public-surface scanner for vibe-coded apps. Paste a deployed app URL and get a shareable report with redacted evidence, confidence labels, grouped findings, and copy-paste remediation.

It is built for solo builders, hackathon teams, and product leads who need a fast launch-readiness check before they submit, demo, or share a public app.

## What It Checks

VibeCheck only inspects public responses, public client assets, and a small set of predictable unauthenticated routes.

- `client_secret`: client-bundle secret exposure, including AI-era keys for DeepSeek, OpenRouter, Pinecone, LangSmith, Langfuse, and Clerk secret keys.
- `client_data_exposure`: risky client-delivered data in Next.js hydration and React Server Component payloads.
- `source_map`: public source-map references and exposed source maps.
- `exposed_infrastructure`: exposed infrastructure paths such as env, git, config, and deployment metadata files.
- `security_headers`, `cors`, and `public_api_surface`: browser security headers, CORS behavior, and referenced public API response-shape metadata.
- `debug_schema_surface`: public schema/debug surfaces at `/openapi.json`, `/swagger.json`, and `/api/graphql`.
- `firebase_config`: Firebase web config in client bundles, routed as a Security Rules self-check.
- `supabase_rls_authorized_probe`: gated Supabase anonymous-read/RLS risk checks, only after explicit owner authorization.

## Responsible-Use Boundary

VibeCheck is read-only public-surface scanning. It may perform bounded GET, HEAD, and OPTIONS requests against the submitted deployed URL and its referenced public assets/routes.

VibeCheck does **not** exploit, mutate, brute force, bypass auth, write to target databases, authenticate as a user, probe discovered IDs, harvest data, or store sensitive target content. You should only scan apps you own or have explicit permission to test.

## What Reports Store

Reports store normalized findings, redacted fingerprints, confidence labels, aggregate-safe metadata, and remediation text.

They do not store:

- Raw secrets.
- Raw source maps or source code.
- Database rows.
- Cookies, authorization headers, or sensitive request headers.
- Full target response bodies.
- Sensitive query strings.
- Raw PII samples from client payloads.

## How A Scan Works

1. The API validates that the submitted target is a public HTTP(S) URL and blocks localhost, private IPs, metadata hosts, unsafe ports, and unsafe redirects.
2. The scanner fetches the public page and bounded public assets within the request budget.
3. Checkers emit normalized `Finding` objects with redacted evidence and `Remediation` guidance.
4. Classification routes the report into Clean, Fixable, Incident, or Incomplete based on the most urgent raw finding.
5. Scoring uses weighted raw findings. Critical incidents cap the hygiene score into the F range.
6. The report UI groups related raw findings for readability while keeping raw findings as the source of truth.

## Local Development

```bash
npm install
npm run dev
```

Then open the local Next.js dev URL shown by the terminal.

## Deploying

Use [docs/deployment/vercel-supabase.md](docs/deployment/vercel-supabase.md) to create the Supabase tables, set Vercel environment variables, and deploy a submit-ready build.

Set `NEXT_PUBLIC_APP_URL` to your production URL. If omitted, VibeCheck falls back to `https://vibecheck-pi-blue.vercel.app` for absolute links.

## Verification

```bash
npm test
npm run typecheck
npm run build
npm run smoke:submission
```

The tests cover URL safety, private-network blocking, redirect target validation, redaction, checker accuracy, classification, report rendering, and XSS-safe evidence handling.

## Safety Controls

Copy `.env.example` to `.env.local` and set:

- `SCANNING_DISABLED=true` to disable all scanning.
- `SUPABASE_PROBE_DISABLED=true` to disable only the gated Supabase probe.
- `DISABLED_CHECKS=security_headers,cors` to disable individual checks during rollout.
- `AUTH_FINGERPRINT_SALT` to a private random value before collecting real authorization artifacts.

## Data Store

Development uses an in-memory report store so the app runs immediately. Production report storage and scan rate limiting require Supabase tables, including `reports`, `events`, `waitlist_entries`, and `rate_limit_events`. In serverless production, rate limiting fails closed if Supabase is not configured.
