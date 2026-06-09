import type { PublicAsset } from "@/lib/types";

function jwtWithRole(role: "anon" | "service_role") {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ role, iss: "supabase", ref: "demo" })).toString(
    "base64url"
  );
  return `${header}.${payload}.signature`;
}

export const supabaseAnonJwt = jwtWithRole("anon");
export const supabaseServiceRoleJwt = jwtWithRole("service_role");

export const cleanAssets: PublicAsset[] = [
  {
    url: "https://clean.example/app.js",
    type: "script",
    body: "console.log('hello world')",
    truncated: false
  }
];

export const leakyAssets: PublicAsset[] = [
  {
    url: "https://leaky.example/app.js",
    type: "script",
    body: `
      const stripe = "sk_live_1234567890abcdefghijkl";
      const supabaseUrl = "https://demo.supabase.co";
      const supabaseKey = "${supabaseServiceRoleJwt}";
    `,
    truncated: false
  }
];

export const xssAsset: PublicAsset = {
  url: "https://xss.example/app.js",
  type: "script",
  body: `const value = "sk_live_1234567890abcdef<script>alert(1)</script>";`,
  truncated: false
};
