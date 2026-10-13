// A fake npm registry + GitHub API for tests. It is plain data, so it can also be
// serialized and loaded by test/preload-fake-fetch.js for the Action integration test.

import { gzipSync } from 'node:zlib';

export const NOW = Date.parse('2026-10-13T12:00:00Z');
export const hoursAgo = (h) => new Date(NOW - h * 3600 * 1000).toISOString();
export const daysAgo = (d) => hoursAgo(d * 24);

// --- tarballs ---------------------------------------------------------------------

function header(name, size, type = '0') {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148); // checksum placeholder
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

export function makeTarball(files) {
  const parts = [];
  for (const [path, content] of Object.entries(files)) {
    const body = Buffer.from(content);
    const full = `package/${path}`;
    if (Buffer.byteLength(full) > 100) {
      // pax extended header carrying the long path
      const rec = (() => {
        const kv = ` path=${full}\n`;
        let len = kv.length + 2;
        while (String(len).length + kv.length !== len) len = String(len).length + kv.length;
        return Buffer.from(`${len}${kv}`);
      })();
      parts.push(header('PaxHeader', rec.length, 'x'), rec, Buffer.alloc((512 - (rec.length % 512)) % 512));
      parts.push(header('long-name-placeholder', body.length));
    } else {
      parts.push(header(full, body.length));
    }
    parts.push(body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

// --- provenance -------------------------------------------------------------------

export function provenanceStatement({ repo, workflow = '.github/workflows/release.yml', ref = 'refs/heads/main', event = 'push', commit, repoId = `id-${repo.toLowerCase()}` }) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: { ref, repository: `https://github.com/${repo}`, path: workflow } },
        internalParameters: { github: { event_name: event, repository_id: repoId, repository_owner_id: `owner-${repo.split('/')[0].toLowerCase()}` } },
        resolvedDependencies: [{ uri: `git+https://github.com/${repo}@${ref}`, digest: { gitCommit: commit } }],
      },
      runDetails: {
        builder: { id: 'https://github.com/actions/runner/github-hosted' },
        metadata: { invocationId: `https://github.com/${repo}/actions/runs/1/attempts/1` },
      },
    },
  };
}

function attestationBody(stmt) {
  return {
    attestations: [
      {
        predicateType: stmt.predicateType,
        bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(stmt)).toString('base64'), payloadType: 'application/vnd.in-toto+json' } },
      },
    ],
  };
}

// --- world ------------------------------------------------------------------------

export function createWorld() {
  return { packages: {}, attestations: {}, tarballs: {}, repos: {}, githubDown: false, files: {} };
}

// release({ name, version, publishedAt, provenance, trusted, npmUser, scripts, files, dependencies })
export function addRelease(world, r) {
  const pkg = (world.packages[r.name] ??= { name: r.name, versions: {}, time: {}, 'dist-tags': {} });
  const tarballUrl = `https://registry.npmjs.org/${r.name}/-/${r.name.split('/').pop()}-${r.version}.tgz`;
  const scripts = r.scripts ?? {};
  const pkgJson = { name: r.name, version: r.version, scripts, dependencies: r.dependencies ?? {} };
  const files = { 'package.json': JSON.stringify(pkgJson), 'index.js': 'module.exports = 1;\n', ...(r.files ?? {}) };
  world.tarballs[tarballUrl] = makeTarball(files).toString('base64');
  pkg.versions[r.version] = {
    name: r.name,
    version: r.version,
    scripts,
    dependencies: r.dependencies ?? {},
    _npmUser: r.trusted
      ? { name: 'GitHub Actions', email: 'npm-oidc-no-reply@github.com', trustedPublisher: { id: 'github', oidcConfigId: r.oidcConfigId ?? 'cfg-1' } }
      : { name: r.npmUser ?? 'maintainer', email: 'm@example.com' },
    dist: { tarball: tarballUrl, unpackedSize: 1000 },
  };
  pkg.time[r.version] = r.publishedAt;
  pkg.time.created ??= r.publishedAt;
  if (Date.parse(r.publishedAt) < Date.parse(pkg.time.created)) pkg.time.created = r.publishedAt;
  pkg['dist-tags'].latest = r.version;
  if (r.provenance) world.attestations[`${r.name}@${r.version}`] = attestationBody(provenanceStatement(r.provenance));
  return pkg;
}

export function removeVersion(world, name, version) {
  delete world.packages[name].versions[version];
}

// repo: { default_branch, branches: { main: [sha...] }, orphans: [sha], pulls: { sha: [prNumber] } }
export function addRepo(world, slug, repo) {
  world.repos[slug.toLowerCase()] = { default_branch: 'main', branches: { main: [] }, orphans: [], pulls: {}, ...repo };
}

// --- fake fetch -------------------------------------------------------------------

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

export function fakeFetch(world, log = []) {
  return async (url, init = {}) => {
    const u = new URL(url);
    log.push(`${init.method || 'GET'} ${u.host}${u.pathname}${u.search}`);
    if (u.host === 'registry.npmjs.org') return registryRoute(world, u);
    if (u.host === 'api.github.com') return githubRoute(world, u, init);
    return new Response('not found', { status: 404 });
  };
}

function registryRoute(world, u) {
  const path = decodeURIComponent(u.pathname);
  const att = /^\/-\/npm\/v1\/attestations\/(.+)@([^@]+)$/.exec(path);
  if (att) {
    const body = world.attestations[`${att[1]}@${att[2]}`];
    return body ? json(body) : json({ error: 'not found' }, 404);
  }
  if (path.includes('/-/')) {
    const b64 = world.tarballs[u.href];
    return b64 ? new Response(Buffer.from(b64, 'base64'), { status: 200 }) : new Response('nope', { status: 404 });
  }
  const pkg = world.packages[path.slice(1)];
  return pkg ? json(pkg) : json({ error: 'not found' }, 404);
}

function githubRoute(world, u, init) {
  if (world.githubDown) return json({ message: 'API rate limit exceeded' }, 403);
  const p = decodeURIComponent(u.pathname);
  let m;
  if ((m = /^\/repos\/([^/]+\/[^/]+)$/.exec(p))) {
    const repo = world.repos[m[1].toLowerCase()];
    return repo ? json({ full_name: m[1], default_branch: repo.default_branch }) : json({ message: 'Not Found' }, 404);
  }
  if ((m = /^\/repos\/([^/]+\/[^/]+)\/compare\/(.+)\.\.\.(.+)$/.exec(p))) {
    const repo = world.repos[m[1].toLowerCase()];
    if (!repo) return json({ message: 'Not Found' }, 404);
    const [, , base, branch] = m;
    const history = repo.branches[branch];
    if (!history) return json({ message: 'Not Found' }, 404);
    if (history.includes(base)) return json({ status: history.at(-1) === base ? 'identical' : 'ahead' });
    if (repo.orphans.includes(base)) return json({ message: 'No common ancestor' }, 404);
    if (Object.values(repo.branches).some((h) => h.includes(base))) return json({ status: 'diverged' });
    return json({ message: 'Not Found' }, 404);
  }
  if ((m = /^\/repos\/([^/]+\/[^/]+)\/commits\/([^/]+)\/pulls$/.exec(p))) {
    const repo = world.repos[m[1].toLowerCase()];
    const prs = repo?.pulls?.[m[2]] ?? [];
    return json(prs.map((n) => ({ number: n, merged_at: '2026-01-01T00:00:00Z' })));
  }
  if ((m = /^\/repos\/([^/]+\/[^/]+)\/commits\/([^/]+)$/.exec(p))) {
    const repo = world.repos[m[1].toLowerCase()];
    const known = repo && (repo.orphans.includes(m[2]) || Object.values(repo.branches).some((h) => h.includes(m[2])));
    return known ? json({ sha: m[2] }) : json({ message: 'No commit found' }, 422);
  }
  if ((m = /^\/repos\/([^/]+\/[^/]+)\/contents\/(.+)$/.exec(p))) {
    const key = `${m[1].toLowerCase()}:${m[2]}@${u.searchParams.get('ref')}`;
    const text = world.files[key];
    return text === undefined ? json({ message: 'Not Found' }, 404) : new Response(text, { status: 200 });
  }
  if ((m = /^\/repos\/([^/]+\/[^/]+)\/issues\/(\d+)\/comments$/.exec(p))) {
    world.comments ??= [];
    if ((init.method || 'GET') === 'POST') {
      const body = JSON.parse(init.body).body;
      world.comments.push({ id: world.comments.length + 1, body });
      return json({ id: world.comments.length }, 201);
    }
    return json(world.comments);
  }
  return json({ message: 'Not Found' }, 404);
}
