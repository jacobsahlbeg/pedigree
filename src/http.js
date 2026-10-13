// Small fetch wrapper: timeouts, one retry on transient errors, and JSON/bytes helpers.
// Every network call in pedigree goes through here so tests can inject a fake fetch.

const USER_AGENT = 'pedigree-check/0.1.0';

export class HttpError extends Error {
  constructor(message, status, url) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.url = url;
  }
}

export function createHttp({ fetchImpl = globalThis.fetch, timeoutMs = 20000, retries = 1 } = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('No fetch implementation available (Node 20+ is required).');
  }

  async function request(url, { headers = {}, method = 'GET', body } = {}) {
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(url, {
          method,
          body,
          headers: { 'user-agent': USER_AGENT, ...headers },
          signal: ctrl.signal,
        });
        // Retry only on server-side hiccups; 4xx answers are meaningful to callers.
        if (res.status >= 500 && attempt < retries) {
          lastErr = new HttpError(`HTTP ${res.status}`, res.status, url);
          continue;
        }
        return res;
      } catch (err) {
        lastErr = err;
        if (attempt >= retries) break;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr;
  }

  // Returns { status, data } where data is parsed JSON, or null for 404.
  async function json(url, opts = {}) {
    const res = await request(url, {
      ...opts,
      headers: { accept: 'application/json', ...(opts.headers || {}) },
    });
    if (res.status === 404) return { status: 404, data: null };
    if (!res.ok) {
      let detail = '';
      try {
        detail = (await res.text()).slice(0, 200);
      } catch {
        /* ignore */
      }
      throw new HttpError(`HTTP ${res.status} for ${url} ${detail}`.trim(), res.status, url);
    }
    return { status: res.status, data: await res.json() };
  }

  // Returns a Buffer, refusing anything larger than maxBytes.
  async function bytes(url, { maxBytes = 25 * 1024 * 1024, headers = {} } = {}) {
    const res = await request(url, { headers });
    if (res.status === 404) return null;
    if (!res.ok) throw new HttpError(`HTTP ${res.status} for ${url}`, res.status, url);
    const declared = Number(res.headers?.get?.('content-length') || 0);
    if (declared && declared > maxBytes) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxBytes) return null;
    return buf;
  }

  return { request, json, bytes };
}
