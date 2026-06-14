export const CHECK_BUDGETS = {
  asset_collection: 10,
  client_bundle_secrets: 10,
  exposed_source_maps: 8,
  exposed_infrastructure: 12,
  security_headers: 1,
  cors: 5,
  public_api_surface: 8,
  supabase_rls_authorized_probe: 5
} as const;

export type CheckId = keyof typeof CHECK_BUDGETS;

const CHECK_IDS = new Set<string>(Object.keys(CHECK_BUDGETS));

export function parseDisabledChecks(input: string) {
  const requested = input
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const disabled = requested.filter((item) => CHECK_IDS.has(item)) as CheckId[];
  const unknown = requested.filter((item) => !CHECK_IDS.has(item));
  return {
    disabled: [...new Set(disabled)],
    unknown: [...new Set(unknown)]
  };
}

export function isCheckEnabled(disabledChecks: readonly string[], checkId: CheckId) {
  return !disabledChecks.includes(checkId);
}
