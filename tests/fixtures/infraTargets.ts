function recorder() {
  const calls: Array<{ url: string; method: string }> = [];
  const record = (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: input.toString(), method: init?.method ?? "GET" });
  };
  return { calls, record };
}

export function infraExposedFetch() {
  const { calls, record } = recorder();
  const fetchImpl: typeof fetch = async (input, init) => {
    record(input, init);
    const url = input.toString();
    if (url.endsWith("/.env")) {
      return new Response("STRIPE_SECRET_KEY=sk_live_fakeinert\nDATABASE_URL=postgres://fake", {
        status: 200
      });
    }
    if (url.endsWith("/.git/config")) {
      return new Response("[core]\n\trepositoryformatversion = 0\n\tbare = false\n", { status: 200 });
    }
    return new Response(null, { status: 404 });
  };
  return { calls, fetchImpl };
}

export function infraExpandedFetch() {
  const { calls, record } = recorder();
  const fetchImpl: typeof fetch = async (input, init) => {
    record(input, init);
    const url = input.toString();
    if (url.endsWith("/.git/HEAD")) {
      return new Response("ref: refs/heads/main\n", { status: 200 });
    }
    if (url.endsWith("/.svn/entries")) {
      return new Response("12\ndir\nmain\n", { status: 200 });
    }
    if (url.endsWith("/.DS_Store")) {
      return new Response("DS_STORE_BINARY_SHAPE_PLACEHOLDER", { status: 200 });
    }
    if (url.endsWith("/config.json")) {
      return new Response('{"apiBase":"/api","debug":false}', { status: 200 });
    }
    if (url.endsWith("/firebase.json")) {
      return new Response('{"hosting":{"public":"dist"}}', { status: 200 });
    }
    if (url.endsWith("/vercel.json")) {
      return new Response('{"rewrites":[{"source":"/api/:path*","destination":"/api/:path*"}]}', {
        status: 200
      });
    }
    if (url.endsWith("/netlify.toml")) {
      return new Response("[build]\n  publish = \"dist\"\n", { status: 200 });
    }
    return new Response(null, { status: 404 });
  };
  return { calls, fetchImpl };
}

export function infraCleanFetch() {
  const { calls, record } = recorder();
  const fetchImpl: typeof fetch = async (input, init) => {
    record(input, init);
    return new Response(null, { status: 404 });
  };
  return { calls, fetchImpl };
}

export function infraSoft404Fetch() {
  const { calls, record } = recorder();
  const fetchImpl: typeof fetch = async (input, init) => {
    record(input, init);
    return new Response("<!DOCTYPE html><html><body>Not found</body></html>", { status: 200 });
  };
  return { calls, fetchImpl };
}
