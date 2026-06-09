export const scanConfig = {
  scanningDisabled: process.env.SCANNING_DISABLED === "true",
  supabaseProbeDisabled: process.env.SUPABASE_PROBE_DISABLED === "true",
  authFingerprintSalt: process.env.AUTH_FINGERPRINT_SALT || "development-only-salt",
  appUrl: process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000",
  supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "",
  supabasePublishableKey: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || "",
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || ""
};
