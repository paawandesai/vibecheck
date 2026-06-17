# VibeCheck Deployment Runbook

This is the shortest path to a submit-ready deployment on Vercel with persistent report storage in Supabase.

## 1. Create The Supabase Project

1. Create a new Supabase project for VibeCheck.
2. Open the SQL editor.
3. Run `supabase/migrations/202606090001_init_vibecheck.sql`.
4. Confirm these tables exist and have RLS enabled:
   - `reports`
   - `events`
   - `waitlist_entries`
   - `rate_limit_events`

The app uses the Supabase service-role key from server routes only. Do not expose it in browser code.

## 2. Collect Environment Variables

Set these in Vercel for Production, Preview, and Development:

```bash
SCANNING_DISABLED=false
SUPABASE_PROBE_DISABLED=false
DISABLED_CHECKS=
AUTH_FINGERPRINT_SALT=<random-long-string>
NEXT_PUBLIC_SUPABASE_URL=https://<project-ref>.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=<publishable-key>
SUPABASE_SERVICE_ROLE_KEY=<server-only-service-role-key>
NEXT_PUBLIC_APP_URL=https://<your-vercel-domain>
NEXT_PUBLIC_PENDO_API_KEY=
PENDO_INTEGRATION_KEY=<server-only-pendo-integration-key>
```

Keep `SUPABASE_SERVICE_ROLE_KEY` server-only. Do not create a `NEXT_PUBLIC_` copy.
Production scan rate limiting requires the Supabase store and `rate_limit_events` table.
Without it, scan requests fail closed instead of using in-memory counters.

## 3. Deploy On Vercel

If using the Vercel dashboard:

1. Push the repo to GitHub.
2. Import the GitHub repo into Vercel.
3. Framework preset should auto-detect as Next.js.
4. Add the environment variables above.
5. Deploy.

If using the Vercel CLI:

```bash
npm exec vercel link
npm exec vercel env add SCANNING_DISABLED production
npm exec vercel env add SUPABASE_PROBE_DISABLED production
npm exec vercel env add DISABLED_CHECKS production
npm exec vercel env add AUTH_FINGERPRINT_SALT production
npm exec vercel env add NEXT_PUBLIC_SUPABASE_URL production
npm exec vercel env add NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY production
npm exec vercel env add SUPABASE_SERVICE_ROLE_KEY production
npm exec vercel env add NEXT_PUBLIC_APP_URL production
npm exec vercel env add NEXT_PUBLIC_PENDO_API_KEY production
npm exec vercel env add PENDO_INTEGRATION_KEY production
npm exec vercel deploy --prod
```

Repeat env additions for `preview` if you want preview deploys to persist reports too.

## 4. Smoke Test The Deployment

1. Open the Vercel URL and confirm the styled landing page loads.
2. Submit `http://localhost:3000`; it should be blocked as an unsafe target.
3. Scan a small deployed fixture app you own.
4. Confirm `/r/[id]` loads after scan completion.
5. In Supabase, confirm one row appears in `reports` and `scan_started` / `scan_completed` rows appear in `events`.
6. Submit the waitlist CTA and confirm an email + hashed email row appears in `waitlist_entries`.
7. Trigger scan requests until a limit is reached and confirm a `429` with `Retry-After`.

## 5. Launch Safety Switches

If anything behaves unexpectedly during the hackathon:

- Set `SCANNING_DISABLED=true` to pause all scanning.
- Set `SUPABASE_PROBE_DISABLED=true` to pause only the gated Supabase probe.
- Set `DISABLED_CHECKS=security_headers,cors` or another comma-separated list to disable individual checks.

Redeploy or restart after changing environment variables if Vercel does not apply them immediately.
