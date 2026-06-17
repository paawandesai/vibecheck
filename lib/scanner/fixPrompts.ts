import type { Builder, FindingType } from "@/lib/types";

const genericPrompts: Record<FindingType, Record<Builder, string>> = {
  client_secret: {
    lovable:
      "Find the exposed key in my frontend code, move it to a server-side action or edge function, rotate the leaked key, and update the app so the browser only receives public keys.",
    bolt:
      "Audit my client bundle for the exposed secret, move the secret into server environment variables, rotate the leaked key, and make any browser call go through a server API route.",
    cursor:
      "Search this repo for the exposed secret fingerprint, remove it from all client-side code, rotate the provider key, and add a server-only wrapper so the browser never receives the secret.",
    replit:
      "Move this secret into Replit Secrets, rotate the leaked value, and update the frontend to call a backend route instead of using the key in browser JavaScript.",
    supabase:
      "If this is a Supabase service_role key, rotate it immediately, keep it server-only, and use anon/publishable keys in the browser only with RLS and least-privilege grants enabled."
  },
  client_data_exposure: {
    lovable:
      "Find the reported client hydration data, remove private fields from props or server component payloads, and keep user records, roles, emails, tokens, and billing data server-side.",
    bolt:
      "Audit the reported Next.js hydration/RSC payload, minimize the serialized data to only what the page needs, and verify private-looking fields are no longer shipped to the browser.",
    cursor:
      "Trace where the reported fields are added to props, loader data, or server component payloads, replace broad object spreads with explicit safe fields, and add a regression check.",
    replit:
      "Remove private fields from browser-delivered page data, keep the full records on the server, redeploy, and view source to confirm the reported keys are gone.",
    supabase:
      "If this data comes from Supabase, select only public columns for browser payloads and rely on RLS plus server routes for private fields."
  },
  source_map: {
    lovable:
      "Disable production source map publishing for this app, redeploy, and verify the .map URL returns 404 or is blocked from public access.",
    bolt:
      "Update the production build settings so source maps are not uploaded publicly, redeploy, and confirm sourceMappingURL files are no longer accessible.",
    cursor:
      "Change the production build config to avoid public source maps, redeploy, and add a deployment check that fails if .map files are publicly served.",
    replit:
      "Disable public production source maps in the build/deploy config, redeploy the app, and confirm the source map URL is no longer accessible.",
    supabase:
      "Source maps are an app deployment issue. Disable public production source maps, redeploy, and avoid exposing source code paths or bundled source content."
  },
  supabase_rls: {
    lovable:
      "Review the Supabase tables used by this app, enable RLS, add least-privilege select policies, and rerun the scan to confirm anonymous reads are blocked.",
    bolt:
      "Open Supabase, enable RLS on the reported table, replace broad public read policies with least-privilege policies, then redeploy and retest.",
    cursor:
      "Add or tighten Supabase RLS policies for the reported table, ensure anonymous users cannot select private rows, and include a regression test for anon access.",
    replit:
      "In Supabase, enable RLS for the reported table, remove broad anon select policies, and update the app to read data only through authorized flows.",
    supabase:
      "Enable RLS on the reported table, remove broad grants to anon/authenticated, add least-privilege policies, and test with the anon key before shipping."
  },
  security_header: {
    lovable:
      "Review the reported response headers, add the missing browser security headers in your hosting or app config, redeploy, and rerun the scan.",
    bolt:
      "Add the missing security headers to the production app config, redeploy, and confirm the response includes the reported protections.",
    cursor:
      "Update the app or hosting header config to add the reported security headers, then add a regression check for production responses.",
    replit:
      "Configure the deployed app to return the reported security headers and retest the public URL after redeploying.",
    supabase:
      "If Supabase Edge Functions serve this route, add the reported security headers in the function response or gateway config."
  },
  cors: {
    lovable:
      "Tighten the reported CORS policy so it only allows trusted origins and never combines wildcard or reflected origins with credentials.",
    bolt:
      "Restrict CORS on the reported endpoint to explicit trusted origins, redeploy, and verify hostile origins are rejected.",
    cursor:
      "Update the CORS middleware for the reported endpoint, add tests for hostile Origin headers, and confirm credentials are not exposed cross-origin.",
    replit:
      "Change the reported route's CORS settings to a least-privilege origin allowlist and retest with a hostile Origin header.",
    supabase:
      "Review Supabase/API gateway CORS settings and restrict browser access to the origins your app actually controls."
  },
  exposed_infrastructure: {
    lovable:
      "Remove the exposed infrastructure file from public routes, redeploy, and verify the path returns 404 or is blocked.",
    bolt:
      "Audit public/static files and route handlers, remove the exposed infrastructure artifact, redeploy, and retest the reported path.",
    cursor:
      "Search for the exposed infrastructure path, remove it from public assets or route handlers, and add a deployment check that blocks it.",
    replit:
      "Remove the exposed file from public hosting, keep secrets in environment storage, and confirm the public path is no longer reachable.",
    supabase:
      "If this is hosted through Supabase or an edge route, remove the exposed config/source artifact and keep privileged values server-only."
  },
  public_api: {
    lovable:
      "Review the reported public API route, require authorization for private data, and avoid returning sensitive JSON shapes to anonymous users.",
    bolt:
      "Lock down the reported API endpoint with auth or server-side filtering, redeploy, and verify anonymous GET requests no longer expose private shapes.",
    cursor:
      "Add authorization checks to the reported API route, redact private fields, and include an anonymous-request regression test.",
    replit:
      "Move private data access behind authenticated server logic and confirm anonymous requests to the reported API path are blocked or sanitized.",
    supabase:
      "If this API reads Supabase data, enforce RLS and least-privilege server routes before returning data to browsers."
  },
  debug_schema: {
    lovable:
      "Restrict the reported OpenAPI, Swagger, or GraphQL debug route in production, require admin authentication, or remove it from the public deploy.",
    bolt:
      "Disable public schema/debug endpoints for production builds and verify unauthenticated GET requests to the reported path no longer return rich schema metadata.",
    cursor:
      "Add a production guard or admin auth check around the reported schema route, then add a test that anonymous production requests do not expose the schema.",
    replit:
      "Hide the reported schema/debug route from the public Replit deployment or require admin authentication before serving it.",
    supabase:
      "If this route documents Supabase-backed APIs, keep private operations behind auth and avoid publishing internal table or policy details."
  },
  firebase_config: {
    lovable:
      "Review Firebase Security Rules for the project used by this frontend config and make sure anonymous users can only access intentionally public data.",
    bolt:
      "Open Firebase Rules for Firestore, Realtime Database, and Storage, replace broad public rules with least-privilege rules, and retest public access.",
    cursor:
      "Audit Firebase initialization usage, confirm the config is public-only, tighten Security Rules, and add emulator tests for anonymous read/write denial.",
    replit:
      "Keep Firebase web config in the frontend if needed, but lock down Firestore, Realtime Database, and Storage Rules before redeploying.",
    supabase:
      "This is a Firebase rules self-check rather than a Supabase issue. Make sure Firebase rules, not the public web config, are enforcing access."
  }
};

export function fixPromptsFor(type: FindingType) {
  return genericPrompts[type];
}
