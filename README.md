# VibeCheck

VibeCheck is a 60-second, read-only security scanner for vibe-coded apps. Paste a deployed app URL and get a shareable report with redacted evidence and copy-paste fix prompts.

## What The Scan Does

VibeCheck performs limited, read-only checks against public app surfaces:

- Client bundle secret exposure.
- Public source map exposure.
- Exposed infrastructure file checks.
- Browser security headers, CORS, and referenced public API shape checks.
- Gated Supabase anonymous-read/RLS risk checks, only after explicit authorization.

VibeCheck does **not** exploit, mutate, brute force, bypass auth, write to target databases, or store sensitive target content. Reports store redacted findings, fingerprints, metadata, confidence labels, and aggregate-safe outcomes only.

## What Is Never Stored

- Raw secrets.
- Raw source maps or source code.
- Database rows.
- Cookies, authorization headers, or sensitive request headers.
- Full target response bodies.
- Sensitive query strings.

## Local Development

```bash
npm install
npm run dev
```

Then open [http://localhost:3000](http://localhost:3000).

## Deploying

Use [docs/deployment/vercel-supabase.md](docs/deployment/vercel-supabase.md) to create the Supabase tables, set Vercel environment variables, and deploy a submit-ready build.

## Verification

```bash
npm test
npm run typecheck
npm run build
```

The tests cover URL safety, private-network blocking, redirect target validation, redaction, checker accuracy, and XSS-safe evidence handling.

## Safety Controls

Copy `.env.example` to `.env.local` and set:

- `SCANNING_DISABLED=true` to disable all scanning.
- `SUPABASE_PROBE_DISABLED=true` to disable only the gated Supabase probe.
- `DISABLED_CHECKS=security_headers,cors` to disable individual checks during rollout.
- `AUTH_FINGERPRINT_SALT` to a private random value before collecting real authorization artifacts.

## MVP Data Store

This scaffold uses an in-memory report store in development so the app runs immediately. Production scan rate limiting requires the Supabase store and `rate_limit_events` table so serverless deployments fail closed instead of relying on process memory.
