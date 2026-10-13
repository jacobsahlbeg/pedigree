// End-to-end rule behavior against a fake registry and GitHub, modeled on the
// 2026 attack patterns: orphan commits (Red Hat / Miasma), swapped workflows and
// pull_request_target (TanStack), stolen tokens plus a fresh dependency (axios),
// binding.gyp payloads, and multi-version publishing bursts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHttp } from '../src/http.js';
import { Registry } from '../src/registry.js';
import { GitHub } from '../src/github.js';
import { analyzePackage } from '../src/analyze.js';
import { createWorld, addRelease, addRepo, removeVersion, fakeFetch, NOW, daysAgo, hoursAgo } from './world.js';

const REPO = 'acme/widget';
const MAIN = ['c1', 'c2', 'c3', 'c4'];

function baseWorld() {
  const world = createWorld();
  addRepo(world, REPO, { branches: { main: [...MAIN] }, pulls: { c2: [10], c3: [11], c4: [12] } });
  addRelease(world, { name: 'widget', version: '1.0.0', publishedAt: daysAgo(60), trusted: true,
    provenance: { repo: REPO, commit: 'c1' } });
  addRelease(world, { name: 'widget', version: '1.1.0', publishedAt: daysAgo(30), trusted: true,
    provenance: { repo: REPO, commit: 'c2' } });
  addRelease(world, { name: 'widget', version: '1.2.0', publishedAt: daysAgo(10), trusted: true,
    provenance: { repo: REPO, commit: 'c3' } });
  return world;
}

function ctxFor(world, { github = true } = {}) {
  const http = createHttp({ fetchImpl: fakeFetch(world), retries: 0 });
  return {
    registry: new Registry({ http }),
    github: github ? new GitHub({ http, token: 't' }) : null,
    now: NOW,
  };
}

const ids = (report) => report.findings.map((f) => f.id);
const sevOf = (report, id) => report.findings.find((f) => f.id === id)?.severity;

test('a normal release from main through a merged PR is clean', async () => {
  const world = baseWorld();
  addRelease(world, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(2), trusted: true,
    provenance: { repo: REPO, commit: 'c4' } });
  const r = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(world));
  assert.equal(r.error, null);
  assert.equal(r.baseline, '1.2.0');
  assert.deepEqual(ids(r), []);
  assert.equal(r.maxSeverity, 'info');
});

test('orphan commit with valid provenance is critical (Red Hat / Miasma pattern)', async () => {
  const world = baseWorld();
  // An attacker pushes a commit with no shared history to a throwaway branch,
  // and the existing release workflow publishes it with valid provenance.
  world.repos[REPO].orphans.push('evil1');
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: hoursAgo(5), trusted: true,
    provenance: { repo: REPO, commit: 'evil1', ref: 'refs/heads/tmp-x9' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD007'), 'critical');
  assert.ok(ids(r).includes('PD006'), 'branch name changed from main');
  assert.equal(r.maxSeverity, 'critical');
});

test('provenance pointing at a commit that does not exist is critical', async () => {
  const world = baseWorld();
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(1), trusted: true,
    provenance: { repo: REPO, commit: 'ghost' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD007'), 'critical');
  assert.match(r.findings.find((f) => f.id === 'PD007').message, /does not exist/);
});

test('swapped workflow on pull_request_target is flagged (TanStack pattern)', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.main.push('c5');
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: hoursAgo(3), trusted: true,
    provenance: { repo: REPO, commit: 'c5', workflow: '.github/workflows/old-bench.yml', event: 'pull_request_target' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD004'), 'high');
  assert.equal(sevOf(r, 'PD005'), 'high');
  assert.match(r.findings.find((f) => f.id === 'PD005').message, /outside the maintainer team/);
});

test('stolen token + fresh dependency with an install script is critical (axios pattern)', async () => {
  const world = baseWorld();
  addRelease(world, { name: 'crypto-helper-js', version: '4.2.1', publishedAt: hoursAgo(20),
    scripts: { postinstall: 'node setup.js' } });
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: hoursAgo(2), trusted: false, npmUser: 'jdoe',
    dependencies: { 'crypto-helper-js': '^4.2.1' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD001'), 'high', 'provenance dropped');
  assert.equal(sevOf(r, 'PD002'), 'high', 'trusted publishing -> token');
  assert.equal(sevOf(r, 'PD012'), 'high', 'young dependency with install hook');
  assert.equal(sevOf(r, 'PD100'), 'critical');
  assert.ok(ids(r).includes('PD014'), 'fresh release noted');
});

test('binding.gyp added with an otherwise normal release path is high but not combined', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.main.push('c4');
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true,
    provenance: { repo: REPO, commit: 'c4' }, files: { 'binding.gyp': "{ 'targets': [] }" } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD010'), 'high');
  assert.ok(!ids(r).includes('PD100'));
});

test('a publishing burst is compared against the settled release, not the burst', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.main.push('c5', 'c6');
  const evil = { repo: REPO, workflow: '.github/workflows/legacy.yml' };
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: hoursAgo(6), trusted: true, provenance: { ...evil, commit: 'c5' } });
  addRelease(world, { name: 'widget', version: '1.2.2', publishedAt: hoursAgo(5), trusted: true, provenance: { ...evil, commit: 'c6' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.2' }, ctxFor(world));
  assert.equal(r.baseline, '1.2.0', 'skips 1.2.1, which is inside the 72h window');
  assert.equal(sevOf(r, 'PD004'), 'high');
});

test('GitHub being unavailable degrades to an info note, registry checks still run', async () => {
  const world = baseWorld();
  world.githubDown = true;
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: false, npmUser: 'jdoe' });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(r.error, null);
  assert.equal(sevOf(r, 'PD001'), 'high');
  // no provenance on target -> lineage isn't attempted at all
  assert.ok(!ids(r).includes('PD007'));

  const world2 = baseWorld();
  world2.githubDown = true;
  addRelease(world2, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(4), trusted: true, provenance: { repo: REPO, commit: 'c4' } });
  const r2 = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(world2));
  assert.equal(sevOf(r2, 'PD016'), 'info');
  assert.match(r2.findings.find((f) => f.id === 'PD016').message, /rate limited/);
});

test('a version removed from the registry is high', async () => {
  const world = baseWorld();
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(1), trusted: true, provenance: { repo: REPO, commit: 'c3' } });
  removeVersion(world, 'widget', '1.2.1');
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD017'), 'high');
});

test('backports from a release branch are fine when the baseline also came from it', async () => {
  const world = createWorld();
  addRepo(world, REPO, { branches: { main: ['m1', 'm2'], 'v1.x': ['b1', 'b2'] }, pulls: { b1: [1], b2: [2] } });
  addRelease(world, { name: 'widget', version: '1.4.0', publishedAt: daysAgo(40), trusted: true, provenance: { repo: REPO, commit: 'b1', ref: 'refs/heads/v1.x' } });
  addRelease(world, { name: 'widget', version: '1.4.1', publishedAt: daysAgo(5), trusted: true, provenance: { repo: REPO, commit: 'b2', ref: 'refs/heads/v1.x' } });
  const r = await analyzePackage({ name: 'widget', version: '1.4.1' }, ctxFor(world));
  assert.deepEqual(ids(r), []);
});

test('commit off main is high when the baseline was on main', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.feature = ['f1'];
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true, provenance: { repo: REPO, commit: 'f1' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD007'), 'high');
});

test('missing merged PR is only flagged when earlier releases had one', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.main.push('direct');
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true, provenance: { repo: REPO, commit: 'direct' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD008'), 'medium');

  // A project that always pushes release commits directly: no finding.
  const w2 = createWorld();
  addRepo(w2, REPO, { branches: { main: ['a', 'b'] } });
  addRelease(w2, { name: 'widget', version: '2.0.0', publishedAt: daysAgo(20), trusted: true, provenance: { repo: REPO, commit: 'a' } });
  addRelease(w2, { name: 'widget', version: '2.0.1', publishedAt: daysAgo(4), trusted: true, provenance: { repo: REPO, commit: 'b' } });
  const r2 = await analyzePackage({ name: 'widget', version: '2.0.1' }, ctxFor(w2));
  assert.ok(!ids(r2).includes('PD008'));
});

test('the first release has no baseline', async () => {
  const world = createWorld();
  addRelease(world, { name: 'brand-new', version: '0.1.0', publishedAt: daysAgo(3) });
  const r = await analyzePackage({ name: 'brand-new', version: '0.1.0' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD015'), 'info');
});

test('new install hook in an otherwise identical release is high; a changed hook is medium', async () => {
  const world = baseWorld();
  world.repos[REPO].branches.main.push('c4');
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true,
    provenance: { repo: REPO, commit: 'c4' }, scripts: { postinstall: 'node ./x.js' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD009'), 'high');

  const w2 = baseWorld();
  w2.packages.widget.versions['1.2.0'].scripts = { install: 'node-gyp-build' };
  w2.repos[REPO].branches.main.push('c4');
  addRelease(w2, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true,
    provenance: { repo: REPO, commit: 'c4' }, scripts: { install: 'node build.js' } });
  // the tarball package.json for 1.2.0 was generated without scripts; drop tarball checks
  const r2 = await analyzePackage({ name: 'widget', version: '1.2.1' }, { ...ctxFor(w2), options: { inspectTarballs: false } });
  assert.equal(sevOf(r2, 'PD009'), 'medium');
});

test('a repository transfer (same GitHub repo ID) is low, a different repository is high', async () => {
  const world = baseWorld();
  addRepo(world, 'newco/widget', { branches: { main: ['c1', 'c2', 'c3', 'c4'] }, pulls: { c4: [12] } });
  addRelease(world, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(2), trusted: true,
    provenance: { repo: 'newco/widget', commit: 'c4', repoId: `id-${REPO}` } });
  const r = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(world));
  assert.equal(sevOf(r, 'PD003'), 'low');

  const w2 = baseWorld();
  addRepo(w2, 'evil/widget', { branches: { main: ['e1'] } });
  addRelease(w2, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(2), trusted: true,
    provenance: { repo: 'evil/widget', commit: 'e1' } });
  const r2 = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(w2));
  assert.equal(sevOf(r2, 'PD003'), 'high');
});

test('a workflow used by a recent settled release is a known path', async () => {
  const world = baseWorld();
  // 1.1.0 was published by a manual dispatch workflow; 1.2.0 by the normal one.
  world.attestations['widget@1.1.0'] = undefined;
  addRelease(world, { name: 'widget', version: '1.1.0', publishedAt: daysAgo(30), trusted: true,
    provenance: { repo: REPO, commit: 'c2', workflow: '.github/workflows/manual-publish.yml', event: 'workflow_dispatch' } });
  world.repos[REPO].branches.main.push('c5');
  world.repos[REPO].pulls.c5 = [13];
  addRelease(world, { name: 'widget', version: '1.2.1', publishedAt: daysAgo(4), trusted: true,
    provenance: { repo: REPO, commit: 'c5', workflow: '.github/workflows/manual-publish.yml', event: 'workflow_dispatch' } });
  const r = await analyzePackage({ name: 'widget', version: '1.2.1' }, ctxFor(world));
  assert.deepEqual(r.history, ['1.2.0', '1.1.0', '1.0.0']);
  assert.ok(!ids(r).includes('PD004'));
  assert.ok(!ids(r).includes('PD005'));
});

test('the oidc: prefix change in trusted-publisher IDs is not a config change', async () => {
  const world = baseWorld();
  world.packages.widget.versions['1.2.0']._npmUser.trustedPublisher.oidcConfigId = 'oidc:abc-123';
  addRelease(world, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(2), trusted: true, oidcConfigId: 'abc-123',
    provenance: { repo: REPO, commit: 'c4' } });
  const r = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(world));
  assert.ok(!ids(r).includes('PD002'));
});

test('a backport compares with its own minor line', async () => {
  const world = baseWorld();
  world.repos[REPO].branches['1.1.x'] = ['c2', 'b1'];
  world.repos[REPO].pulls.b1 = [20];
  addRelease(world, { name: 'widget', version: '1.1.1', publishedAt: daysAgo(1), trusted: true,
    provenance: { repo: REPO, commit: 'b1' } });
  const r = await analyzePackage({ name: 'widget', version: '1.1.1' }, ctxFor(world));
  assert.equal(r.baseline, '1.1.0');
});

test('runs without GitHub at all', async () => {
  const world = baseWorld();
  addRelease(world, { name: 'widget', version: '1.3.0', publishedAt: daysAgo(2), trusted: true, provenance: { repo: REPO, commit: 'c4' } });
  const r = await analyzePackage({ name: 'widget', version: '1.3.0' }, ctxFor(world, { github: false }));
  assert.equal(sevOf(r, 'PD016'), 'info');
  assert.equal(r.maxSeverity, 'info');
});
