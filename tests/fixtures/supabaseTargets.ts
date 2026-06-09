import { supabaseAnonJwt } from "./assets";

export const supabaseContext = {
  url: "https://example.com",
  anonKey: supabaseAnonJwt,
  serviceRoleKeyFingerprints: []
};

export function publicResolver() {
  return Promise.resolve([{ address: "93.184.216.34" }]);
}

export function supabaseReadableFetch() {
  const calls: Array<{ url: string; method: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = input.toString();
    const method = init?.method ?? "GET";
    calls.push({ url, method });

    if (url.endsWith("/rest/v1/")) {
      return new Response(JSON.stringify({ paths: {} }), { status: 200 });
    }

    if (url.includes("/rest/v1/profiles") && method === "HEAD") {
      return new Response(null, {
        status: 200,
        headers: {
          "content-range": "0-0/3"
        }
      });
    }

    if (url.includes("/rest/v1/profiles")) {
      return new Response(JSON.stringify([{ email: "secret-row@example.com" }]), { status: 200 });
    }

    return new Response(null, { status: 401 });
  };

  return { calls, fetchImpl };
}

export function supabaseProtectedFetch() {
  const calls: Array<{ url: string; method: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = input.toString();
    const method = init?.method ?? "GET";
    calls.push({ url, method });
    return new Response(null, { status: 401 });
  };

  return { calls, fetchImpl };
}
