// GitHub REST client for lineage questions:
//   - Is the commit a release was built from part of the default branch's history?
//   - Did that commit arrive through a merged pull request?
// The token is only ever sent to the configured API host.

export class GitHubUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = 'GitHubUnavailable';
  }
}

export class GitHub {
  constructor({ http, token = null, apiBase = 'https://api.github.com' } = {}) {
    if (!http) throw new Error('GitHub needs an http client');
    this.http = http;
    this.token = token;
    this.apiBase = apiBase.replace(/\/$/, '');
    this.cache = new Map();
    this.unavailable = null; // set once we hit auth/rate-limit errors
  }

  headers(extra = {}) {
    const h = { 'x-github-api-version': '2022-11-28', ...extra };
    if (this.token) h.authorization = `Bearer ${this.token}`;
    return h;
  }

  async get(path, { accept } = {}) {
    if (this.unavailable) throw new GitHubUnavailable(this.unavailable);
    const key = `${accept || ''} ${path}`;
    if (this.cache.has(key)) return this.cache.get(key);
    const p = (async () => {
      const res = await this.http.request(`${this.apiBase}${path}`, {
        headers: this.headers(accept ? { accept } : { accept: 'application/vnd.github+json' }),
      });
      if (res.status === 401 || res.status === 403 || res.status === 429) {
        const body = await safeText(res);
        this.unavailable = `GitHub API returned ${res.status}${/rate limit/i.test(body) ? ' (rate limited)' : ''}`;
        throw new GitHubUnavailable(this.unavailable);
      }
      if (res.status === 404 || res.status === 422) return { status: res.status, data: null };
      if (!res.ok) throw new Error(`GitHub API ${res.status} for ${path}`);
      const data = accept && accept.includes('raw') ? await res.text() : await res.json();
      return { status: res.status, data };
    })();
    this.cache.set(key, p);
    return p;
  }

  async repo(owner, repo) {
    const r = await this.get(`/repos/${owner}/${repo}`);
    return r.data;
  }

  async commitExists(owner, repo, sha) {
    const r = await this.get(`/repos/${owner}/${repo}/commits/${sha}`);
    return r.status === 200;
  }

  // Is `sha` an ancestor of (or equal to) `branch`'s current head?
  // Returns { reachable: true|false|null, orphan, missing }.
  async isAncestor(owner, repo, sha, branch) {
    const r = await this.get(
      `/repos/${owner}/${repo}/compare/${encodeURIComponent(sha)}...${encodeURIComponent(branch)}?per_page=1`,
    );
    if (r.data) {
      // compare(base=sha, head=branch): "ahead"/"identical" means branch contains sha.
      const status = r.data.status;
      return { reachable: status === 'ahead' || status === 'identical', orphan: false, missing: false, status };
    }
    // 404 means either no common ancestor (an orphan commit) or no such commit.
    const exists = await this.commitExists(owner, repo, sha);
    return { reachable: false, orphan: exists, missing: !exists, status: exists ? 'no-common-ancestor' : 'missing' };
  }

  // Full lineage picture for one release commit.
  async lineage(owner, repo, sha, refBranch = null) {
    const info = await this.repo(owner, repo);
    if (!info) return { repoFound: false };
    const defaultBranch = info.default_branch;
    const onDefault = await this.isAncestor(owner, repo, sha, defaultBranch);
    let onRefBranch = null;
    if (!onDefault.reachable && !onDefault.missing && refBranch && refBranch !== defaultBranch) {
      onRefBranch = await this.isAncestor(owner, repo, sha, refBranch);
    }
    return {
      repoFound: true,
      defaultBranch,
      onDefault: onDefault.reachable,
      orphan: onDefault.orphan,
      missing: onDefault.missing,
      compareStatus: onDefault.status,
      onRefBranch: onRefBranch ? onRefBranch.reachable : null,
    };
  }

  // Merged pull requests associated with a commit.
  async mergedPulls(owner, repo, sha) {
    const r = await this.get(`/repos/${owner}/${repo}/commits/${sha}/pulls?per_page=10`);
    if (!Array.isArray(r.data)) return [];
    return r.data.filter((pr) => pr && pr.merged_at).map((pr) => pr.number);
  }

  // Raw file contents at a ref (used by the Action to read the base lockfile).
  async fileAt(owner, repo, path, ref) {
    const encoded = path.split('/').map(encodeURIComponent).join('/');
    const r = await this.get(`/repos/${owner}/${repo}/contents/${encoded}?ref=${encodeURIComponent(ref)}`, {
      accept: 'application/vnd.github.raw+json',
    });
    return r.data;
  }
}

async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return '';
  }
}
