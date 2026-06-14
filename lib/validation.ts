const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function isUuid(value: string | undefined | null) {
  return Boolean(value && UUID_PATTERN.test(value));
}

export function normalizeOptionalReportId(value: unknown) {
  if (value === undefined || value === null || value === "") return { ok: true as const };
  if (typeof value !== "string" || !isUuid(value)) {
    return { ok: false as const, error: "reportId must be a valid UUID." };
  }
  return { ok: true as const, reportId: value };
}

export function normalizeEmail(value: unknown) {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return EMAIL_PATTERN.test(email) ? email : null;
}
