import { isSupabaseStoreConfigured, recordRateLimitHit, rateLimitCountSince } from "@/lib/store/supabaseStore";

export interface RateLimitInput {
  requesterFingerprint: string;
  targetOrigin: string;
  now?: Date;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds?: number;
  reason?: string;
}

const limits = [
  { scope: "requester_hour", max: 25, windowMs: 60 * 60 * 1000 },
  { scope: "requester_day", max: 100, windowMs: 24 * 60 * 60 * 1000 },
  { scope: "origin_hour", max: 50, windowMs: 60 * 60 * 1000 }
] as const;

type LimitScope = (typeof limits)[number]["scope"];

declare global {
  // eslint-disable-next-line no-var
  var __vibecheckRateLimitHits:
    | Array<{ scope: LimitScope; key: string; createdAt: number }>
    | undefined;
}

const memoryHits = globalThis.__vibecheckRateLimitHits ?? [];
globalThis.__vibecheckRateLimitHits = memoryHits;

function keyFor(scope: LimitScope, input: RateLimitInput) {
  return scope === "origin_hour" ? input.targetOrigin : input.requesterFingerprint;
}

function retryAfterSeconds(windowMs: number) {
  return Math.ceil(windowMs / 1000);
}

async function checkSupabase(input: RateLimitInput, now: Date) {
  for (const limit of limits) {
    const key = keyFor(limit.scope, input);
    const since = new Date(now.getTime() - limit.windowMs);
    const count = await rateLimitCountSince(limit.scope, key, since);
    if (count >= limit.max) {
      return {
        allowed: false,
        retryAfterSeconds: retryAfterSeconds(limit.windowMs),
        reason: `${limit.scope} limit exceeded`
      };
    }
  }

  await Promise.all(
    limits.map((limit) => recordRateLimitHit(limit.scope, keyFor(limit.scope, input), now))
  );
  return { allowed: true };
}

function checkMemory(input: RateLimitInput, now: Date) {
  const nowMs = now.getTime();
  for (const limit of limits) {
    const cutoff = nowMs - limit.windowMs;
    const key = keyFor(limit.scope, input);
    const count = memoryHits.filter(
      (hit) => hit.scope === limit.scope && hit.key === key && hit.createdAt >= cutoff
    ).length;
    if (count >= limit.max) {
      return {
        allowed: false,
        retryAfterSeconds: retryAfterSeconds(limit.windowMs),
        reason: `${limit.scope} limit exceeded`
      };
    }
  }

  for (const limit of limits) {
    memoryHits.push({
      scope: limit.scope,
      key: keyFor(limit.scope, input),
      createdAt: nowMs
    });
  }

  const oldestWindow = nowMs - 24 * 60 * 60 * 1000;
  for (let i = memoryHits.length - 1; i >= 0; i -= 1) {
    if (memoryHits[i].createdAt < oldestWindow) memoryHits.splice(i, 1);
  }

  return { allowed: true };
}

export async function consumeScanRateLimit(input: RateLimitInput): Promise<RateLimitResult> {
  const now = input.now ?? new Date();
  if (process.env.NODE_ENV !== "production") {
    return checkMemory(input, now);
  }

  if (isSupabaseStoreConfigured()) {
    return checkSupabase(input, now);
  }

  return {
    allowed: false,
    retryAfterSeconds: 60,
    reason: "Production rate limiting requires Supabase storage."
  };
}
