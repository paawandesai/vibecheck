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
  }
};

export function fixPromptsFor(type: FindingType) {
  return genericPrompts[type];
}
