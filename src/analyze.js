// Orchestrates the checks for one package version: pick a baseline release,
// gather facts about both, run the rules, and combine the findings.

import { parseProvenance } from './provenance.js';
import { listTarball, summarizeTarball } from './tarball.js';
import { GitHubUnavailable } from './github.js';
import {
  compareProvenance,
  comparePublishMethod,
  compareLineage,
  comparePayload,
  dependencyFindings,
  escalate,
  finding,
  installHooks,
  maxSeverity,
  sevRank,
} from './rules.js';

export const DEFAULTS = {
  baselineGapHours: 72, // worms publish in bursts; compare against something older than the burst
  freshHours: 24,
  youngDependencyDays: 30,
  inspectTarballs: true,
  maxTarballBytes: 25 * 1024 * 1024,
  maxUnpackedBytes: 200 * 1024 * 1024,
  maxNewDependencies: 10,
  historySize: 5, // earlier settled releases whose release paths count as "known"
};

const isPrerelease = (v) => /^\d+\.\d+\.\d+-/.test(v);

// Picks the comparison baseline plus a short history of earlier settled releases.
//
//  - "Settled" means published at least `gapHours` before the target. Worms publish
//    several malicious versions within hours; a settled baseline sits outside the burst.
//  - Candidates are tried from the closest release line outward: same minor
//    (backports like 19.0.8 compare with 19.0.7), then same major, then anything.
//  - Prereleases are skipped unless the target is one.
//
// Returns { version, settled, history: [versions] } or null when nothing earlier exists.
export function chooseBaseline(packument, version, { gapHours = DEFAULTS.baselineGapHours, explicit = null, historySize = DEFAULTS.historySize } = {}) {
  if (explicit) {
    return packument.versions?.[explicit] ? { version: explicit, settled: true, explicit: true, history: [explicit] } : null;
  }
  const times = packument.time || {};
  const targetTime = Date.parse(times[version]);
  if (Number.isNaN(targetTime)) return null;
  const allowPre = isPrerelease(version);
  const earlier = Object.keys(packument.versions || {})
    .filter((v) => v !== version && (allowPre || !isPrerelease(v)))
    .map((v) => ({ v, t: Date.parse(times[v]) }))
    .filter((x) => !Number.isNaN(x.t) && x.t < targetTime)
    .sort((a, b) => b.t - a.t);
  if (!earlier.length) return null;
  const cutoff = targetTime - gapHours * 3600 * 1000;
  const pools = [
    earlier.filter((x) => minorLine(x.v) === minorLine(version)),
    earlier.filter((x) => releaseLine(x.v) === releaseLine(version)),
    earlier,
  ];
  for (let i = 0; i < pools.length; i++) {
    const settled = pools[i].filter((x) => x.t <= cutoff);
    if (settled.length) {
      // Within a line, the nearest lower version is the natural predecessor (so 19.3.0
      // compares with 19.2.x, not with a 19.0.x backport published last week).
      const lower = settled.filter((x) => compareSemver(x.v, version) < 0).sort((a, b) => compareSemver(b.v, a.v));
      const pick = lower[0] || settled[0];
      // The history of "known" release paths widens until it has enough releases:
      // major line first, then everything (new majors have little history of their own).
      const history = [pick];
      for (const pool of pools.slice(Math.max(i, 1))) {
        for (const x of pool) {
          if (history.length >= historySize) break;
          if (x.t <= cutoff && !history.some((h) => h.v === x.v)) history.push(x);
        }
      }
      return { version: pick.v, settled: true, history: history.map((x) => x.v) };
    }
  }
  const nearest = pools.find((p) => p.length)[0];
  return { version: nearest.v, settled: false, history: [nearest.v] };
}

// "3.4.5" -> "3", "0.30.1" -> "0.30"
export function releaseLine(v) {
  const [major, minor] = v.split('.');
  return major === '0' ? `0.${minor}` : major;
}

export function compareSemver(a, b) {
  const pa = a.split(/[-+]/)[0].split('.').map(Number);
  const pb = b.split(/[-+]/)[0].split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

// "3.4.5" -> "3.4", "0.30.1" -> "0.30"
function minorLine(v) {
  const [major, minor] = v.split('.');
  return `${major}.${minor}`;
}

function publisherOf(manifest) {
  const u = manifest?._npmUser;
  if (!u) return null;
  return {
    name: u.name || null,
    trusted: Boolean(u.trustedPublisher),
    // npm dropped the "oidc:" prefix from these IDs in September 2026; same config either way.
    oidcConfigId: u.trustedPublisher?.oidcConfigId ? String(u.trustedPublisher.oidcConfigId).replace(/^oidc:/, '') : null,
  };
}

// Lightweight facts for the history window: no tarballs, just how each release was made.
async function pathFacts(registry, packument, version) {
  const att = await registry.attestations(packument.name, version).catch(() => ({ provenance: null }));
  return { version, provenance: parseProvenance(att.provenance), publisher: publisherOf(packument.versions[version]) };
}

async function inspectTarball(registry, manifest, opts) {
  if (!opts.inspectTarballs) return null;
  const url = manifest?.dist?.tarball;
  if (!url) return null;
  if (manifest.dist.unpackedSize && manifest.dist.unpackedSize > opts.maxUnpackedBytes) return null;
  try {
    const buf = await registry.tarball(url, opts.maxTarballBytes);
    if (!buf) return null;
    return summarizeTarball(listTarball(buf, { maxUnpackedBytes: opts.maxUnpackedBytes }));
  } catch {
    return null;
  }
}

async function releaseFacts(registry, packument, version, opts) {
  const manifest = packument.versions[version];
  const [att, tarball] = await Promise.all([
    registry.attestations(packument.name, version).catch(() => ({ provenance: null })),
    inspectTarball(registry, manifest, opts),
  ]);
  // The packed package.json is what npm actually runs; fall back to registry metadata.
  const scripts = tarball?.packageJson?.scripts ?? manifest.scripts ?? {};
  return {
    version,
    publishedAt: packument.time?.[version] || null,
    manifest,
    provenance: parseProvenance(att.provenance),
    publisher: publisherOf(manifest),
    scripts,
    tarball,
    dependencies: Object.keys({ ...(manifest.dependencies || {}), ...(manifest.optionalDependencies || {}) }),
  };
}

async function newDependencyFacts(registry, names, now) {
  return Promise.all(
    names.map(async (name) => {
      try {
        const p = await registry.packument(name);
        if (!p) return { name, missing: true, ageDays: null, hasInstallHooks: false };
        const created = Date.parse(p.time?.created);
        const latest = p.versions?.[p['dist-tags']?.latest];
        return {
          name,
          missing: false,
          ageDays: Number.isNaN(created) ? null : (now - created) / 86400000,
          hasInstallHooks: Object.keys(installHooks(latest?.scripts)).length > 0,
        };
      } catch {
        return { name, missing: false, ageDays: null, hasInstallHooks: false };
      }
    }),
  );
}

async function lineageFacts(github, target, baseline) {
  const t = target.provenance;
  const result = { target: null, baseline: null, targetPulls: null, baselinePulls: null };
  const refBranch = t.ref.kind === 'branch' ? t.ref.name : null;
  result.target = await github.lineage(t.owner, t.repo, t.commit, refBranch);
  if (!result.target.repoFound || result.target.missing || result.target.orphan) return result;

  const b = baseline?.provenance;
  const sameRepo = b && b.host === 'github.com' && b.repository === t.repository && b.commit;
  if (result.target.onDefault === false && sameRepo) {
    result.baseline = await github.lineage(b.owner, b.repo, b.commit, b.ref.kind === 'branch' ? b.ref.name : null);
  }
  result.targetPulls = await github.mergedPulls(t.owner, t.repo, t.commit);
  if (result.targetPulls.length === 0 && sameRepo) {
    result.baselinePulls = await github.mergedPulls(b.owner, b.repo, b.commit);
  }
  return result;
}

export async function analyzePackage({ name, version, previous = [] }, { registry, github = null, options = {}, now = Date.now() }) {
  const opts = { ...DEFAULTS, ...options };
  const report = {
    name,
    version,
    previous,
    baseline: null,
    baselineSettled: null,
    publishedAt: null,
    provenance: null,
    findings: [],
    maxSeverity: 'info',
    error: null,
  };

  try {
    const packument = await registry.packument(name);
    if (!packument) {
      report.findings.push(finding('PD017', 'high', `"${name}" is not on the registry.`));
      return finalize(report);
    }
    if (!packument.versions?.[version]) {
      report.findings.push(finding('PD017', 'high',
        `${name}@${version} is not on the registry anymore. Versions are usually removed because they were malicious or broken.`));
      return finalize(report);
    }

    const base = chooseBaseline(packument, version, { gapHours: opts.baselineGapHours, explicit: opts.baseline });
    const target = await releaseFacts(registry, packument, version, opts);
    report.publishedAt = target.publishedAt;
    report.provenance = target.provenance && {
      repository: target.provenance.repository,
      workflow: target.provenance.workflowPath,
      event: target.provenance.eventName,
      ref: target.provenance.workflowRef,
      commit: target.provenance.commit,
      run: target.provenance.runUrl,
    };

    const ageHours = (now - Date.parse(target.publishedAt)) / 3600000;
    if (ageHours >= 0 && ageHours < opts.freshHours) {
      report.findings.push(finding('PD014', 'low',
        `Published ${Math.max(1, Math.round(ageHours))} hour(s) ago. Most malicious releases are caught and removed within a day.`,
        { ageHours }));
    }

    if (!base) {
      report.findings.push(finding('PD015', 'info', 'This is the first release in its channel, so there is no earlier release to compare against.'));
      return finalize(report);
    }
    report.baseline = base.version;
    report.baselineSettled = base.settled;
    if (!base.settled) {
      report.findings.push(finding('PD015', 'info',
        `No release older than ${opts.baselineGapHours}h exists, so the comparison uses ${base.version}, which may be part of the same publishing burst.`));
    }

    const [baseline, ...older] = await Promise.all([
      releaseFacts(registry, packument, base.version, opts),
      ...base.history.filter((v) => v !== base.version).map((v) => pathFacts(registry, packument, v)),
    ]);
    const history = [baseline, ...older];
    report.history = history.map((h) => h.version);

    report.findings.push(...compareProvenance(target, baseline, history));
    report.findings.push(...comparePublishMethod(target, baseline, history));
    report.findings.push(...comparePayload(target, baseline));

    const added = target.dependencies.filter((d) => !baseline.dependencies.includes(d)).slice(0, opts.maxNewDependencies);
    if (added.length) {
      report.findings.push(...dependencyFindings(await newDependencyFacts(registry, added, now), { youngDays: opts.youngDependencyDays }));
    }

    const t = target.provenance;
    if (!t) {
      // Nothing to trace. PD001 already covers "it used to have provenance".
    } else if (t.host !== 'github.com' || !t.commit) {
      report.findings.push(finding('PD016', 'info', 'Provenance does not point at a GitHub commit, so source-history checks were skipped.'));
    } else if (!github) {
      report.findings.push(finding('PD016', 'info', 'Source-history checks are off (no GitHub token was provided).'));
    } else {
      try {
        const lineage = await lineageFacts(github, target, baseline);
        report.findings.push(...compareLineage(target, baseline, lineage));
      } catch (err) {
        report.findings.push(finding('PD016', 'info',
          err instanceof GitHubUnavailable ? `Source-history checks skipped: ${err.message}.` : `Source-history checks failed: ${err.message}`));
      }
    }
  } catch (err) {
    report.error = err.message || String(err);
  }
  return finalize(report);
}

function finalize(report) {
  report.findings = escalate(report.findings).sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.id.localeCompare(b.id));
  report.maxSeverity = maxSeverity(report.findings);
  return report;
}

// Runs fn over items with at most `limit` in flight.
export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function analyzeChanges(changes, ctx, { concurrency = 4, maxPackages = 200 } = {}) {
  const list = changes.slice(0, maxPackages);
  const reports = await mapLimit(list, concurrency, (c) => analyzePackage(c, ctx));
  return { reports, skipped: Math.max(0, changes.length - list.length) };
}
