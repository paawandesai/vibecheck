import type { FindingType, Remediation, RunbookCode, StackProfile } from "@/lib/types";

const INCIDENT_GREP =
  "grep -RInE 'service_role|sk_(live|test)_|sk-proj-|sk-or-v1-|sk-lf-|pcsk_|lsv2_|postgres(ql)?://|mongodb(\\+srv)?://|redis://|-----BEGIN .*PRIVATE KEY-----' . --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git";

const SUPABASE_AUDIT_SQL = `select created_at, ip_address, payload
from auth.audit_log_entries
where created_at >= '<LOOKBACK_START_ISO>'
order by created_at desc
limit 200;`;

const EMERGENCY_ROTATION_CONTEXT =
  "If active abuse is suspected, rotate or revoke the exposed access immediately even if that causes downtime. If you do not see active abuse, locate usage first so you can rotate without breaking production.";

const CSP_BASELINE_CONTEXT =
  "This baseline mainly adds frame, sniff, referrer, and transport defenses. It still uses unsafe-inline and unsafe-eval so it does not provide strong XSS protection yet; tighten scripts with nonces or hashes once you know your app's real script needs.";

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
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }
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
          "value": "max-age=63072000; includeSubDomains"
        }
      ]
    }
  ]
}`;

const NETLIFY_SECURITY_HEADERS = `[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    X-Content-Type-Options = "nosniff"
    Referrer-Policy = "strict-origin-when-cross-origin"
    X-Frame-Options = "DENY"
    Strict-Transport-Security = "max-age=63072000; includeSubDomains"`;

const DJANGO_SECURITY_HEADERS = `# settings.py
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
X_FRAME_OPTIONS = "DENY"
REFERRER_POLICY = "strict-origin-when-cross-origin"

# Add django-csp or equivalent middleware, then start with:
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": ("'self'",),
        "script-src": ("'self'", "'unsafe-inline'", "'unsafe-eval'"),
        "style-src": ("'self'", "'unsafe-inline'"),
        "img-src": ("'self'", "data:", "https:"),
        "font-src": ("'self'", "data:"),
        "connect-src": ("'self'", "https:"),
        "frame-ancestors": ("'none'",),
        "base-uri": ("'self'",),
        "form-action": ("'self'",)
    }
}`;

const GENERIC_SECURITY_HEADERS = `# Add these headers at your CDN, reverse proxy, or hosting edge.
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: DENY
Strict-Transport-Security: max-age=63072000; includeSubDomains`;

const RLS_LOCKDOWN_SQL = `alter table public.<TABLE_NAME> enable row level security;

drop policy if exists "Public read" on public.<TABLE_NAME>;

create policy "Users can read their own rows"
on public.<TABLE_NAME>
for select
to authenticated
using (auth.uid() = user_id);`;

const CLIENT_DATA_MINIMIZE_SNIPPET = `// Before returning props, loader data, or an RSC payload:
const safeUser = {
  id: user.id,
  displayName: user.displayName
};

// Do not serialize private fields like email, phone, role, tokens, internal notes, or billing IDs.
return { props: { user: safeUser } };`;

const DEBUG_SCHEMA_RESTRICT_SNIPPET = `// Example route guard for production schema/debug endpoints.
if (process.env.NODE_ENV === "production") {
  return new Response("Not found", { status: 404 });
}

// In production, serve OpenAPI/GraphQL explorers only behind admin authentication.`;

const FIREBASE_RULES_SNIPPET = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    match /{document=**} {
      allow read, write: if false;
    }
  }
}`;

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
  HEADER_HARDEN: [],
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
  ],
  CLIENT_DATA_MINIMIZE: [
    {
      type: "code",
      snippet: CLIENT_DATA_MINIMIZE_SNIPPET,
      targetLocation: "Next.js props, loader, or server component boundary",
      beginnerContext:
        "Anything serialized into __NEXT_DATA__ or an RSC stream is delivered to the browser. Send only the fields the page needs, and keep private records, roles, tokens, billing data, and internal notes on the server."
    },
    {
      type: "dashboard_instruction",
      snippet:
        "After reducing the payload, reload the public page, view source, and search for the reported field names. Then rescan the deployed URL.",
      targetLocation: "Browser view-source and VibeCheck rescan",
      beginnerContext:
        "This confirms the sensitive-looking data is no longer shipped in the initial HTML or client payload."
    }
  ],
  DEBUG_SCHEMA_RESTRICT: [
    {
      type: "code",
      snippet: DEBUG_SCHEMA_RESTRICT_SNIPPET,
      targetLocation: "OpenAPI, Swagger, or GraphQL route",
      beginnerContext:
        "Schema and explorer routes are useful during development, but in production they can map your API for anonymous visitors. Hide them, require admin auth, or serve a reduced public schema."
    },
    {
      type: "config",
      snippet:
        "Block /openapi.json, /swagger.json, and /api/graphql explorer responses at the edge unless the request is authenticated as an admin.",
      targetLocation: "Hosting edge, reverse proxy, or route middleware",
      beginnerContext:
        "VibeCheck only made unauthenticated GET requests to predictable debug paths. If those routes are intentionally public, document why and make sure private operations are not advertised."
    }
  ],
  FIREBASE_RULES_SELF_CHECK: [
    {
      type: "dashboard_instruction",
      snippet:
        "Open Firebase Console, review Firestore, Realtime Database, and Storage Rules, and confirm anonymous users can only read or write data that is intentionally public.",
      targetLocation: "Firebase Console > Rules",
      beginnerContext:
        "Firebase web config is usually public by design. The real safety control is Security Rules, not hiding the apiKey."
    },
    {
      type: "config",
      snippet: FIREBASE_RULES_SNIPPET,
      targetLocation: "Firebase Security Rules",
      beginnerContext:
        "This is a safer Firestore starting point: users can access their own document and everything else is denied until you add specific rules."
    }
  ]
};

function headerRemediations(stack?: StackProfile): Remediation[] {
  const generic: Remediation = {
    type: "config",
    snippet: GENERIC_SECURITY_HEADERS,
    targetLocation: "CDN, reverse proxy, or hosting edge",
    beginnerContext:
      `Use this when VibeCheck cannot confidently identify the framework or host. Add the headers where public responses are served, redeploy, then rescan. ${CSP_BASELINE_CONTEXT}`
  };
  const next: Remediation = {
    type: "config",
    snippet: NEXT_SECURITY_HEADERS,
    targetLocation: "next.config.js",
    beginnerContext:
      `This is a conservative Next.js starting point. After adding it, test auth, payments, uploads, analytics, and embedded widgets because CSP may require app-specific allowlists. ${CSP_BASELINE_CONTEXT}`
  };
  const vercel: Remediation = {
    type: "config",
    snippet: VERCEL_SECURITY_HEADERS,
    targetLocation: "vercel.json",
    beginnerContext:
      `Use this only for apps deployed on Vercel, where headers can be managed at the routing layer. After deploying, test auth, payments, uploads, analytics, and embedded widgets. ${CSP_BASELINE_CONTEXT}`
  };
  const netlify: Remediation = {
    type: "config",
    snippet: NETLIFY_SECURITY_HEADERS,
    targetLocation: "netlify.toml",
    beginnerContext:
      `Use this for Netlify-hosted apps. Add the headers block, redeploy, and test any embedded widgets or third-party scripts. ${CSP_BASELINE_CONTEXT}`
  };
  const django: Remediation = {
    type: "config",
    snippet: DJANGO_SECURITY_HEADERS,
    targetLocation: "Django settings.py and middleware",
    beginnerContext:
      `Use this for Django-backed apps. Make sure SecurityMiddleware is enabled, install/configure a CSP middleware, then test login, uploads, payments, and admin pages. ${CSP_BASELINE_CONTEXT}`
  };

  if (stack?.backend === "django") return [django, generic];
  if (stack?.host === "vercel") return stack.framework === "next" ? [next, vercel] : [vercel, generic];
  if (stack?.host === "netlify") return stack.framework === "next" ? [next, netlify] : [netlify, generic];
  if (stack?.framework === "next") return [next, generic];
  return [generic];
}

export function remediationsFor(code: RunbookCode, _type?: FindingType, stack?: StackProfile) {
  if (code === "HEADER_HARDEN") return headerRemediations(stack);
  return catalog[code].map((item) => ({ ...item }));
}
