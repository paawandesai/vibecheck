import type { NextConfig } from "next";

const scriptSrc =
  process.env.NODE_ENV === "production"
    ? "script-src 'self' 'unsafe-inline' https://cdn.pendo.io"
    : "script-src 'self' 'unsafe-inline' 'unsafe-eval'";

const upgradeInsecureRequests =
  process.env.NODE_ENV === "production" ? "; upgrade-insecure-requests" : "";

const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value:
      `default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; ${scriptSrc}; connect-src 'self' https://*.pendo.io; form-action 'self'${upgradeInsecureRequests}`
  },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()"
  },
  { key: "X-Robots-Tag", value: "noindex, nofollow" }
];

const appSecurityHeaders = securityHeaders.filter((header) => header.key !== "X-Robots-Tag");

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: appSecurityHeaders
      },
      {
        source: "/r/:path*",
        headers: securityHeaders
      },
      {
        source: "/api/:path*",
        headers: securityHeaders
      }
    ];
  }
};

export default nextConfig;
