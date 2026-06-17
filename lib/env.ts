export const scanConfig = {
  scanningDisabled: process.env.SCANNING_DISABLED === "true",
  supabaseProbeDisabled: process.env.SUPABASE_PROBE_DISABLED === "true",
  disabledChecks: process.env.DISABLED_CHECKS || "",
  authFingerprintSalt: process.env.AUTH_FINGERPRINT_SALT || "development-only-salt",
  appUrl: process.env.NEXT_PUBLIC_APP_URL || "https://vibecheck-pi-blue.vercel.app",
  pendoApiKey: process.env.NEXT_PUBLIC_PENDO_API_KEY || "",
  pendoIntegrationKey: process.env.PENDO_INTEGRATION_KEY || "",
  supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "",
  supabasePublishableKey: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || "",
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || ""
};
