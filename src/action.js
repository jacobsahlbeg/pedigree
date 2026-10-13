// GitHub Action entry point. Runs on pull_request (or push) events, diffs the
// lockfile(s) against the base commit, checks every newly introduced version,
// and reports through the job summary, annotations, outputs, and optionally a PR comment.
//
// Deliberately does not need, and should not be run under, pull_request_target.

import { readFileSync, existsSync, appendFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { createHttp } from './http.js';
import { Registry } from './registry.js';
import { GitHub, GitHubUnavailable } from './github.js';
import { parseLockfile, diffLockfiles, LOCKFILE_NAMES } from './lockfile.js';
import { analyzeChanges } from './analyze.js';
import { applyIgnores, loadConfig } from './config.js';
import { toMarkdown, toJson, shouldFail, overallSeverity, COMMENT_MARKER } from './report.js';
import { sevRank } from './rules.js';

const input = (name, fallback = '') => {
  const v = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  return v === undefined || v === '' ? fallback : v.trim();
};
const bool = (v) => /^(true|yes|1|on)$/i.test(v);

function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}
function escapeProp(s) {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}
function annotate(level, file, title, message) {
  console.log(`::${level} file=${escapeProp(file)},title=${escapeProp(title)}::${escapeData(message)}`);
}
function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

function readBaseFile(workspace, sha, path) {
  try {
    return execFileSync('git', ['show', `${sha}:${path}`], {
      cwd: workspace,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return undefined; // not fetched locally; fall back to the API
  }
}

async function upsertComment(http, token, repo, issue, body, hasFindings) {
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const headers = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'content-type': 'application/json',
    'x-github-api-version': '2022-11-28',
  };
  const list = await http.request(`${api}/repos/${repo}/issues/${issue}/comments?per_page=100`, { headers });
  if (!list.ok) throw new Error(`listing comments failed: HTTP ${list.status}`);
  const existing = (await list.json()).find((c) => typeof c.body === 'string' && c.body.includes(COMMENT_MARKER));
  if (!existing && !hasFindings) return 'skipped';
  const url = existing
    ? `${api}/repos/${repo}/issues/comments/${existing.id}`
    : `${api}/repos/${repo}/issues/${issue}/comments`;
  const res = await http.request(url, { method: existing ? 'PATCH' : 'POST', headers, body: JSON.stringify({ body }) });
  if (!res.ok) throw new Error(`writing comment failed: HTTP ${res.status}`);
  return existing ? 'updated' : 'created';
}

async function run() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const repoSlug = process.env.GITHUB_REPOSITORY || '';
  const [owner, repo] = repoSlug.split('/');
  const event = process.env.GITHUB_EVENT_PATH && existsSync(process.env.GITHUB_EVENT_PATH)
    ? JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'))
    : {};

  if (process.env.GITHUB_EVENT_NAME === 'pull_request_target') {
    annotate('warning', 'action.yml', 'pedigree',
      'pedigree is running under pull_request_target. Use pull_request instead: this check never needs write access to the base repository.');
  }

  const failOn = input('fail-on', 'high');
  const showFrom = input('show', 'low');
  const token = input('github-token');
  const maxPackages = Number(input('max-packages', '200'));
  const baseSha = input('base-ref') || event.pull_request?.base?.sha || event.before;
  if (!baseSha || /^0+$/.test(baseSha)) {
    throw new Error('Could not determine the base commit. Run on pull_request events or set the base-ref input.');
  }

  const listed = input('lockfile')
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  const lockfiles = listed.length ? listed : LOCKFILE_NAMES.filter((n) => existsSync(join(workspace, n)));
  if (!lockfiles.length) {
    console.log('pedigree: no lockfile found; nothing to check.');
    setOutput('max-severity', 'info');
    setOutput('flagged-count', '0');
    return 0;
  }

  const http = createHttp();
  const registry = new Registry({ http, base: input('registry-url', 'https://registry.npmjs.org') });
  const github = token ? new GitHub({ http, token, apiBase: process.env.GITHUB_API_URL || 'https://api.github.com' }) : null;

  // Collect every newly introduced name@version across the lockfiles.
  const seen = new Map();
  const origin = new Map(); // name@version -> lockfile path, for annotations
  for (const path of lockfiles) {
    const full = join(workspace, path);
    if (!existsSync(full)) {
      console.log(`pedigree: ${path} does not exist in this commit; skipping.`);
      continue;
    }
    const headText = readFileSync(full, 'utf8');
    let baseText = readBaseFile(workspace, baseSha, path);
    if (baseText === undefined && github && owner) {
      try {
        baseText = await github.fileAt(owner, repo, path, baseSha);
      } catch (err) {
        if (!(err instanceof GitHubUnavailable)) throw err;
      }
    }
    if (baseText === undefined) {
      throw new Error(`Could not read ${path} at ${baseSha}. Use actions/checkout with fetch-depth: 0, or pass github-token.`);
    }
    const base = baseText ? parseLockfile(path, baseText) : new Map();
    const head = parseLockfile(path, headText);
    for (const change of diffLockfiles(base, head)) {
      const key = `${change.name}@${change.version}`;
      if (!seen.has(key)) {
        seen.set(key, change);
        origin.set(key, path);
      }
    }
  }

  const changes = [...seen.values()];
  console.log(`pedigree: ${changes.length} new package version(s) to check across ${lockfiles.join(', ')}.`);

  const ctx = {
    registry,
    github,
    options: {
      inspectTarballs: bool(input('inspect-tarballs', 'true')),
      baselineGapHours: Number(input('baseline-gap-hours', '72')),
    },
  };
  let { reports, skipped } = await analyzeChanges(changes, ctx, { maxPackages });
  reports = applyIgnores(reports, loadConfig(join(workspace, input('config', '.github/pedigree.json'))));

  // Annotations
  for (const r of reports) {
    const file = origin.get(`${r.name}@${r.version}`) || lockfiles[0];
    for (const f of r.findings) {
      const level = sevRank(f.severity) >= sevRank(failOn) && failOn !== 'none' ? 'error'
        : sevRank(f.severity) >= sevRank('medium') ? 'warning' : null;
      if (level) annotate(level, file, `${r.name}@${r.version}: ${f.id} ${f.rule}`, f.message);
    }
    if (r.error) annotate('warning', file, `${r.name}@${r.version}`, `could not analyze: ${r.error}`);
  }

  const markdown = toMarkdown(reports, { minSeverity: showFrom, skipped, failOn });
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);

  const reportPath = join(process.env.RUNNER_TEMP || workspace, 'pedigree-report.json');
  writeFileSync(reportPath, toJson(reports, { skipped, base: baseSha }));
  const flagged = reports.filter((r) => r.findings.some((f) => sevRank(f.severity) >= sevRank('medium'))).length;
  setOutput('max-severity', overallSeverity(reports));
  setOutput('flagged-count', String(flagged));
  setOutput('report-path', reportPath);

  if (bool(input('comment', 'false')) && token && event.pull_request?.number) {
    try {
      const result = await upsertComment(http, token, repoSlug, event.pull_request.number, markdown, flagged > 0);
      console.log(`pedigree: PR comment ${result}.`);
    } catch (err) {
      annotate('warning', lockfiles[0], 'pedigree', `Could not post the PR comment (${err.message}). Grant "pull-requests: write" to enable it.`);
    }
  }

  const fail = shouldFail(reports, failOn);
  console.log(fail
    ? `pedigree: failing because at least one finding is ${failOn} or worse.`
    : `pedigree: done. Highest severity: ${overallSeverity(reports)}.`);
  return fail ? 1 : 0;
}

run().then(
  (code) => process.exit(code),
  (err) => {
    console.log(`::error title=pedigree::${escapeData(err.message || String(err))}`);
    process.exit(2);
  },
);
