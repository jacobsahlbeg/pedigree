// Runs src/action.js as GitHub would: env inputs, an event payload, a workspace
// with the head lockfile, and the base lockfile fetched through the API.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWorld, addRelease, addRepo, daysAgo } from './world.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const BASE = 'basesha000';

function lockfile(deps) {
  const packages = { '': { name: 'app', version: '1.0.0' } };
  for (const [name, version] of Object.entries(deps)) {
    packages[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2);
}

function setup({ headDeps, inputs = {}, wsFiles = {} }) {
  const world = createWorld();
  addRepo(world, 'acme/widget', { branches: { main: ['c1', 'c2', 'c3'] }, orphans: ['evil'], pulls: { c2: [1], c3: [2] } });
  addRelease(world, { name: 'widget', version: '1.0.0', publishedAt: daysAgo(40), trusted: true, provenance: { repo: 'acme/widget', commit: 'c1' } });
  addRelease(world, { name: 'widget', version: '1.1.0', publishedAt: daysAgo(10), trusted: true, provenance: { repo: 'acme/widget', commit: 'c3' } });
  addRelease(world, { name: 'widget', version: '1.1.1', publishedAt: daysAgo(2), trusted: true,
    provenance: { repo: 'acme/widget', commit: 'evil', ref: 'refs/heads/x' } });
  addRelease(world, { name: 'helper', version: '2.0.0', publishedAt: daysAgo(30) });
  addRelease(world, { name: 'helper', version: '2.0.1', publishedAt: daysAgo(5) });
  world.files[`acme/app:package-lock.json@${BASE}`] = lockfile({ widget: '1.0.0', helper: '2.0.0' });

  const dir = mkdtempSync(join(tmpdir(), 'pedigree-action-'));
  const ws = join(dir, 'ws');
  spawnSync('mkdir', ['-p', ws]);
  writeFileSync(join(ws, 'package-lock.json'), lockfile(headDeps));
  for (const [rel, content] of Object.entries(wsFiles)) {
    spawnSync('mkdir', ['-p', join(ws, rel, '..')]);
    writeFileSync(join(ws, rel), content);
  }
  const eventPath = join(dir, 'event.json');
  writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 7, base: { sha: BASE } } }));
  const worldPath = join(dir, 'world.json');
  writeFileSync(worldPath, JSON.stringify(world));
  for (const f of ['summary.md', 'output.txt']) writeFileSync(join(dir, f), '');

  const env = {
    PATH: process.env.PATH,
    PEDIGREE_FAKE_WORLD: worldPath,
    GITHUB_WORKSPACE: ws,
    GITHUB_EVENT_PATH: eventPath,
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_REPOSITORY: 'acme/app',
    GITHUB_STEP_SUMMARY: join(dir, 'summary.md'),
    GITHUB_OUTPUT: join(dir, 'output.txt'),
    RUNNER_TEMP: dir,
    'INPUT_GITHUB-TOKEN': 'test-token',
    'INPUT_FAIL-ON': 'high',
    ...inputs,
  };
  const run = spawnSync(process.execPath, ['--import', join(root, 'test/preload-fake-fetch.js'), join(root, 'src/action.js')], {
    env,
    encoding: 'utf8',
  });
  return {
    run,
    summary: readFileSync(join(dir, 'summary.md'), 'utf8'),
    outputs: readFileSync(join(dir, 'output.txt'), 'utf8'),
    world: JSON.parse(readFileSync(worldPath, 'utf8')),
    report: () => JSON.parse(readFileSync(join(dir, 'pedigree-report.json'), 'utf8')),
  };
}

test('flags an orphan-commit release, fails the check, annotates, and comments', () => {
  const { run, summary, outputs, world, report } = setup({
    headDeps: { widget: '1.1.1', helper: '2.0.1' },
    inputs: { INPUT_COMMENT: 'true' },
  });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.match(run.stdout, /::error file=package-lock\.json,title=widget@1\.1\.1%3A PD007 commit-off-main::/);
  assert.match(summary, /widget@1\.1\.1/);
  assert.match(summary, /1 of 2 upgraded package\(s\) need review/);
  assert.match(outputs, /max-severity=critical/);
  assert.match(outputs, /flagged-count=1/);
  assert.equal(world.comments.length, 1);
  assert.match(world.comments[0].body, /pedigree-report/);
  const r = report();
  assert.equal(r.reports.find((x) => x.name === 'widget').baseline, '1.1.0');
});

test('passes a clean upgrade and does not post a comment', () => {
  const { run, outputs, world } = setup({ headDeps: { widget: '1.1.0', helper: '2.0.1' }, inputs: { INPUT_COMMENT: 'true' } });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(outputs, /flagged-count=0/);
  assert.equal((world.comments || []).length, 0);
});

test('fail-on none reports but never fails', () => {
  const { run } = setup({ headDeps: { widget: '1.1.1', helper: '2.0.0' }, inputs: { 'INPUT_FAIL-ON': 'none' } });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /::warning file=package-lock\.json/);
});

test('an ignore entry with a reason clears the finding', () => {
  const ignore = {
    ignore: [{ package: 'widget', version: '1.1.1', rule: '*', reason: 'confirmed with maintainers in issue #42' }],
  };
  const { run, outputs } = setup({
    headDeps: { widget: '1.1.1', helper: '2.0.0' },
    wsFiles: { '.github/pedigree.json': JSON.stringify(ignore) },
  });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(outputs, /flagged-count=0/);
});

test('rejects being run under pull_request_target with a warning', () => {
  const { run } = setup({ headDeps: { widget: '1.1.0', helper: '2.0.0' }, inputs: { GITHUB_EVENT_NAME: 'pull_request_target' } });
  assert.match(run.stdout, /::warning .*pull_request_target/);
});
