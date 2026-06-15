import type { FindingType, Remediation, RunbookCode } from "@/lib/types";

const INCIDENT_GREP =
  "grep -RInE 'service_role|sk_(live|test)_|sk-proj-|postgres(ql)?://|mongodb(\\+srv)?://|redis://|-----BEGIN .*PRIVATE KEY-----' . --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git";

const SUPABASE_AUDIT_SQL = `select created_at, ip_address, payload
from auth.audit_log_entries
where created_at >= '<LOOKBACK_START_ISO>'
order by created_at desc
limit 200;`;

const EMERGENCY_ROTATION_CONTEXT =
  "If active abuse is suspected, rotate or revoke the exposed access immediately even if that causes downtime. If you do not see active abuse, locate usage first so you can rotate without breaking production.";

const NEXT_SECURITY_HEADERS = `const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join("; ")
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }
];

module.exports = {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  }
};`;

const VERCEL_SECURITY_HEADERS = `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "X-Frame-Options", "value": "DENY" },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=63072000; includeSubDomains; preload"
        }
      ]
    }
  ]
}`;

const RLS_LOCKDOWN_SQL = `alter table public.<TABLE_NAME> enable row level security;

drop policy if exists "Public read" on public.<TABLE_NAME>;

create policy "Users can read their own rows"
on public.<TABLE_NAME>
for select
to authenticated
using (auth.uid() = user_id);`;

const catalog: Record<RunbookCode, Remediation[]> = {
  INFO_ONLY: [
    {
      type: "dashboard_instruction",
      snippet: "No immediate action is required. Keep public keys public-only and privileged keys server-only.",
      targetLocation: "Project settings",
      beginnerContext:
        "Some keys are designed to be visible in browser apps. They are only safe when backend permissions are still locked down."
    }
  ],
  RLS_SELF_CHECK: [
    {
      type: "dashboard_instruction",
      snippet:
        "Open Supabase Table Editor, select the reported table or storage bucket, enable RLS, and remove broad public read policies unless the data is intentionally public.",
      targetLocation: "Supabase dashboard",
      beginnerContext:
        "The browser is allowed to know your anon key. The important question is whether that key can read private rows or list private buckets."
    },
    {
      type: "sql",
      snippet:
        "alter table public.<TABLE_NAME> enable row level security;\n\n-- Replace this with a policy that matches your app's signed-in user model.\ncreate policy \"Users can read their own rows\"\non public.<TABLE_NAME>\nfor select\nto authenticated\nusing (auth.uid() = user_id);",
      targetLocation: "Supabase SQL Editor",
      beginnerContext:
        "This turns on row-level security and shows the shape of a safer policy. Replace <TABLE_NAME> and user_id with your real table and owner column."
    }
  ],
  RLS_LOCKDOWN_INCIDENT: [
    {
      type: "dashboard_instruction",
      snippet:
        "Open Supabase, identify the reported table, and revoke broad anonymous read access. If active abuse is suspected, rotate/revoke exposed access immediately before preserving uptime.",
      targetLocation: "Supabase dashboard",
      beginnerContext: EMERGENCY_ROTATION_CONTEXT
    },
    {
      type: "sql",
      snippet: RLS_LOCKDOWN_SQL,
      targetLocation: "Supabase SQL Editor",
      beginnerContext:
        "This enables row-level security, removes a broad public read policy if one exists, and replaces it with an owner-only example. Replace <TABLE_NAME> and user_id with your real table and owner column."
    },
    {
      type: "dashboard_instruction",
      snippet:
        "Review Supabase API Gateway, Auth, and Postgres logs from <LOOKBACK_START_ISO>. Look for unfamiliar IPs, repeated anonymous requests, unexpected endpoints, and unusual row-count patterns.",
      targetLocation: "Supabase Logs",
      beginnerContext:
        "Confirmed anonymous reads on likely private tables can expose user data. Logs help you decide whether anyone accessed it before you locked it down."
    },
    {
      type: "sql",
      snippet: SUPABASE_AUDIT_SQL,
      targetLocation: "Supabase SQL Editor",
      beginnerContext:
        "Use your deploy or suspected exposure time as <LOOKBACK_START_ISO>. Look for IP addresses, endpoints, or access patterns you do not recognize."
    }
  ],
  INCIDENT_ROTATE: [
    {
      type: "shell",
      snippet: INCIDENT_GREP,
      targetLocation: "Terminal at the project root",
      beginnerContext: EMERGENCY_ROTATION_CONTEXT
    },
    {
      type: "dashboard_instruction",
      snippet:
        "Review Vercel, Replit, Supabase, and provider dashboards for the leaked key. Create a replacement key, deploy the replacement first, then revoke the exposed key.",
      targetLocation: "Provider dashboards",
      beginnerContext:
        "Rotation means making a new key, moving the app to it, and then turning off the old exposed key."
    },
    {
      type: "sql",
      snippet: SUPABASE_AUDIT_SQL,
      targetLocation: "Supabase SQL Editor",
      beginnerContext:
        "Use your suspected exposure time as <LOOKBACK_START_ISO>. Look for IP addresses, endpoints, or access patterns you do not recognize."
    },
    {
      type: "config",
      snippet:
        "Move privileged secrets into server-only environment variables. Browser code should call your server route, and the server route should call the provider with the secret.",
      targetLocation: "Vercel/Replit environment settings and server route",
      beginnerContext:
        "The fix is architectural: the browser should never receive keys that can bypass your security."
    }
  ],
  INCIDENT_ROTATE_HISTORICAL: [
    {
      type: "shell",
      snippet: "git log --all --oneline --decorate -- .env .env.local .env.production && " + INCIDENT_GREP,
      targetLocation: "Terminal at the project root",
      beginnerContext:
        "A secret in git history should be treated as exposed if the repo or history was public, even if the current file is clean."
    },
    {
      type: "dashboard_instruction",
      snippet:
        "Rotate the historical secret at the provider, then inspect logs from the first public commit containing the value through today.",
      targetLocation: "Provider dashboards",
      beginnerContext:
        "Historical leaks are still leaks because anyone who copied the old commit may still have the key."
    },
    {
      type: "sql",
      snippet: SUPABASE_AUDIT_SQL,
      targetLocation: "Supabase SQL Editor",
      beginnerContext:
        "Set <LOOKBACK_START_ISO> to the timestamp of the first public commit or deployment that contained the secret."
    }
  ],
  MANUAL_TRIAGE: [
    {
      type: "dashboard_instruction",
      snippet:
        "Review the reported value or endpoint owner. If it grants access, rotate it or require authentication; if it is harmless, document why.",
      targetLocation: "Code owner review",
      beginnerContext:
        "VibeCheck found something shaped like risk but cannot prove what it controls from public surfaces alone."
    }
  ],
  SOURCE_MAP_DISABLE: [
    {
      type: "config",
      snippet:
        "Disable public production source maps in your framework or hosting build settings, redeploy, then confirm the reported .map URL returns 404 or is blocked.",
      targetLocation: "Build and deployment settings",
      beginnerContext:
        "Source maps can reveal original source paths and code structure. They are useful for debugging, but should not be public by default."
    }
  ],
  INFRA_REMOVE: [
    {
      type: "config",
      snippet:
        "Remove the reported file from public/static hosting, keep secrets in environment storage, redeploy, and verify the path no longer returns 200.",
      targetLocation: "Public assets, route handlers, and hosting config",
      beginnerContext:
        "Files like .env, .git metadata, and deployment config can reveal how your app works or expose secrets directly."
    }
  ],
  HEADER_HARDEN: [
    {
      type: "config",
      snippet: NEXT_SECURITY_HEADERS,
      targetLocation: "next.config.js",
      beginnerContext:
        "This is a conservative Next.js starting point for browser security headers. After adding it, test auth, payments, uploads, analytics, and embedded widgets because CSP may require app-specific allowlists."
    },
    {
      type: "config",
      snippet: VERCEL_SECURITY_HEADERS,
      targetLocation: "vercel.json",
      beginnerContext:
        "Use this when headers are easier to manage at the Vercel routing layer. After deploying, test auth, payments, uploads, analytics, and embedded widgets because CSP may require app-specific allowlists."
    }
  ],
  CORS_TIGHTEN: [
    {
      type: "code",
      snippet:
        "const allowedOrigins = new Set(['https://your-app.example']);\nconst origin = request.headers.get('origin');\nif (origin && allowedOrigins.has(origin)) {\n  response.headers.set('Access-Control-Allow-Origin', origin);\n  response.headers.set('Vary', 'Origin');\n}",
      targetLocation: "CORS middleware or API route",
      beginnerContext:
        "CORS should name the sites you trust. It should not reflect any website that asks."
    }
  ],
  API_AUTH_REVIEW: [
    {
      type: "code",
      snippet:
        "if (!session?.user) {\n  return Response.json({ error: 'Unauthorized' }, { status: 401 });\n}\n\nreturn Response.json(redactPrivateFields(data));",
      targetLocation: "The reported API route",
      beginnerContext:
        "Public APIs should not return private-looking data to anonymous visitors. Require auth or redact fields before returning JSON."
    }
  ]
};

export function remediationsFor(code: RunbookCode, _type?: FindingType) {
  return catalog[code].map((item) => ({ ...item }));
}
