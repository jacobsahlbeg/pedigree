// Rule catalog and the pure comparison logic. Everything here works on already
// fetched facts, so it is easy to test and to reason about.

import { RISKY_EVENTS } from './provenance.js';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const sevRank = (s) => SEVERITIES.indexOf(s);
export const maxSeverity = (findings) =>
  findings.reduce((m, f) => (sevRank(f.severity) > sevRank(m) ? f.severity : m), 'info');

export const RULES = {
  PD001: { name: 'provenance-dropped', group: 'path', summary: 'Earlier releases had build provenance; this one does not.' },
  PD002: { name: 'publish-method-changed', group: 'path', summary: 'Published differently than before (trusted publishing vs. a token, or a new trusted-publisher config).' },
  PD003: { name: 'source-repo-changed', group: 'path', summary: 'Built from a different source repository than before.' },
  PD004: { name: 'workflow-changed', group: 'path', summary: 'Built by a different workflow file than before.' },
  PD005: { name: 'trigger-changed', group: 'path', summary: 'The release run was started by a different kind of event than before.' },
  PD006: { name: 'ref-changed', group: 'path', summary: 'Built from a different kind of ref (branch vs. tag) or a different branch than before.' },
  PD007: { name: 'commit-off-main', group: 'path', summary: 'The source commit is not part of the default branch history.' },
  PD008: { name: 'no-merged-pr', group: 'path', summary: 'The source commit did not come from a merged pull request, unlike before.' },
  PD009: { name: 'install-script-added', group: 'payload', summary: 'Adds an install-time script (preinstall, install, postinstall).' },
  PD010: { name: 'native-build-added', group: 'payload', summary: 'Adds a binding.gyp, which triggers a native build on install.' },
  PD011: { name: 'native-binary-added', group: 'payload', summary: 'Ships new compiled binaries.' },
  PD012: { name: 'new-dependency', group: 'payload', summary: 'Adds a runtime dependency.' },
  PD013: { name: 'publisher-changed', group: 'context', summary: 'Published by a different npm account than before.' },
  PD014: { name: 'fresh-release', group: 'context', summary: 'Published very recently.' },
  PD015: { name: 'no-baseline', group: 'context', summary: 'No earlier settled release to compare against.' },
  PD016: { name: 'lineage-unchecked', group: 'context', summary: 'Source-history checks could not run.' },
  PD017: { name: 'version-missing', group: 'context', summary: 'This version is no longer on the registry (often removed for security reasons).' },
  PD100: { name: 'path-and-payload-changed', group: 'combined', summary: 'The release path changed and the release adds code that runs on install.' },
};

export function finding(id, severity, message, evidence = {}) {
  return { id, rule: RULES[id].name, severity, message, evidence };
}

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

export function installHooks(scripts) {
  if (!scripts || typeof scripts !== 'object') return {};
  const out = {};
  for (const hook of INSTALL_HOOKS) if (typeof scripts[hook] === 'string') out[hook] = scripts[hook];
  return out;
}

// --- release-path rules ------------------------------------------------------

// `history` is the baseline plus a few earlier settled releases. A value the target
// shares with any of them is a known release path for this project, not a new one.
// (Many projects legitimately alternate, e.g. tag pushes plus manual dispatches.)
const refSignature = (ref) => (ref.kind === 'branch' ? `branch:${ref.name}` : ref.kind);

export function compareProvenance(target, baseline, history = [baseline]) {
  const out = [];
  const t = target.provenance;
  const b = baseline.provenance;
  const known = (pick, value) => history.some((h) => h.provenance && pick(h.provenance) === value);

  if (b && !t) {
    const mixed = history.some((h) => !h.provenance);
    out.push(finding('PD001', mixed ? 'medium' : 'high',
      `${baseline.version} was published with build provenance, but ${target.version} has none.` +
        (mixed ? ' Some recent releases also lacked provenance, so this project is inconsistent about it.'
          : ' Publishes with a stolen npm token usually look like this.'),
      { baseline: b.repository }));
    return out; // nothing else to compare on the path side
  }
  if (!t || !b) return out;

  if (t.repository && b.repository && t.repository !== b.repository && !known((p) => p.repository, t.repository)) {
    if (t.repositoryId && b.repositoryId && t.repositoryId === b.repositoryId) {
      out.push(finding('PD003', 'low',
        `Repository is now ${t.repository} (was ${b.repository}). Same GitHub repository ID, so it was renamed or transferred.`,
        { from: b.repository, to: t.repository, repositoryId: t.repositoryId }));
    } else {
      out.push(finding('PD003', 'high', `Built from ${t.repository}; ${baseline.version} was built from ${b.repository}.`,
        { from: b.repository, to: t.repository, fromId: b.repositoryId, toId: t.repositoryId }));
    }
  }
  if (t.workflowPath && b.workflowPath && t.workflowPath !== b.workflowPath && !known((p) => p.workflowPath, t.workflowPath)) {
    out.push(finding('PD004', 'high', `Built by ${t.workflowPath}; recent releases were built by ${b.workflowPath}.`,
      { from: b.workflowPath, to: t.workflowPath }));
  }
  const risky = t.eventName && RISKY_EVENTS.has(t.eventName);
  if (t.eventName && b.eventName && t.eventName !== b.eventName && !known((p) => p.eventName, t.eventName)) {
    out.push(finding('PD005', risky ? 'high' : 'medium',
      `Release run was triggered by "${t.eventName}"; recent releases were triggered by "${b.eventName}".` +
        (risky ? ` "${t.eventName}" can be started by people outside the maintainer team.` : ''),
      { from: b.eventName, to: t.eventName }));
  } else if (risky && !known((p) => p.eventName, t.eventName)) {
    out.push(finding('PD005', 'high', `Release run was triggered by "${t.eventName}".`, { to: t.eventName }));
  }
  const tk = t.ref.kind;
  const bk = b.ref.kind;
  if (tk && bk && refSignature(t.ref) !== refSignature(b.ref) && !known((p) => refSignature(p.ref), refSignature(t.ref))) {
    out.push(finding('PD006', 'medium',
      `Built from ${describeRef(t.ref)}; recent releases were built from ${describeRef(b.ref)}.`,
      { from: b.workflowRef, to: t.workflowRef }));
  }
  return out;
}

function describeRef(ref) {
  if (ref.kind === 'branch') return `branch "${ref.name}"`;
  if (ref.kind === 'tag') return 'a tag';
  if (ref.kind === 'pull') return `pull request ref "${ref.name}"`;
  return `ref "${ref.name}"`;
}

export function comparePublishMethod(target, baseline, history = [baseline]) {
  const t = target.publisher;
  const b = baseline.publisher;
  if (!t || !b) return [];
  const pubs = history.map((h) => h.publisher).filter(Boolean);
  if (b.trusted && !t.trusted) {
    const tokenBefore = pubs.some((p) => !p.trusted);
    return [finding('PD002', tokenBefore ? 'medium' : 'high',
      `${baseline.version} was published through trusted publishing (OIDC), but ${target.version} was published by the npm account "${t.name}".` +
        (tokenBefore ? ' Some recent releases were also token-published.' : ''),
      { from: 'trusted-publishing', to: t.name })];
  }
  if (b.trusted && t.trusted && b.oidcConfigId && t.oidcConfigId && b.oidcConfigId !== t.oidcConfigId &&
      !pubs.some((p) => p.oidcConfigId === t.oidcConfigId)) {
    return [finding('PD002', 'medium', 'Published through a different trusted-publisher configuration than recent releases.',
      { from: b.oidcConfigId, to: t.oidcConfigId })];
  }
  if (!b.trusted && !t.trusted && b.name && t.name && b.name !== t.name && !pubs.some((p) => p.name === t.name)) {
    return [finding('PD013', 'low', `Published by "${t.name}"; recent releases were published by "${b.name}".`,
      { from: b.name, to: t.name })];
  }
  return [];
}

// lineage = { target, baseline } results from GitHub.lineage(), plus merged PR lists.
export function compareLineage(target, baseline, lineage) {
  const out = [];
  const t = lineage.target;
  if (!t) return out;
  const commit = target.provenance?.commit;

  if (t.repoFound === false) {
    out.push(finding('PD007', 'medium',
      'The source repository named in the provenance could not be found (deleted, made private, or the token cannot see it).', { commit }));
    return out;
  }
  if (t.missing) {
    out.push(finding('PD007', 'critical',
      `Commit ${short(commit)} does not exist in ${target.provenance.repository}. The provenance points at code that is not in the repository.`,
      { commit }));
  } else if (t.orphan) {
    out.push(finding('PD007', 'critical',
      `Commit ${short(commit)} shares no history with "${t.defaultBranch}". It is an orphan commit, the pattern used to publish malicious releases from compromised accounts.`,
      { commit, defaultBranch: t.defaultBranch }));
  } else if (t.onDefault === false) {
    const b = lineage.baseline;
    const baselineOff = b && b.onDefault === false;
    const onReleaseBranch = t.onRefBranch === true;
    if (!baselineOff) {
      out.push(finding('PD007', onReleaseBranch ? 'medium' : 'high',
        `Commit ${short(commit)} is not part of "${t.defaultBranch}"` +
          (onReleaseBranch ? ` (it is on "${target.provenance.ref.name}")` : '') +
          `, while ${baseline.version} was built from "${t.defaultBranch}" history.`,
        { commit, defaultBranch: t.defaultBranch, compare: t.compareStatus }));
    }
  }

  if (lineage.targetPulls && lineage.targetPulls.length === 0 && lineage.baselinePulls && lineage.baselinePulls.length > 0) {
    out.push(finding('PD008', 'medium',
      `Commit ${short(commit)} is not linked to any merged pull request, but ${baseline.version}'s commit came from PR #${lineage.baselinePulls[0]}.`,
      { commit }));
  }
  return out;
}

// --- payload rules -------------------------------------------------------------

export function comparePayload(target, baseline) {
  const out = [];
  const tHooks = installHooks(target.scripts);
  const bHooks = installHooks(baseline.scripts);
  for (const [hook, cmd] of Object.entries(tHooks)) {
    if (!(hook in bHooks)) {
      out.push(finding('PD009', 'high', `Adds a "${hook}" script: ${truncate(cmd, 120)}`, { hook, command: cmd }));
    } else if (bHooks[hook] !== cmd) {
      out.push(finding('PD009', 'medium', `Changes the "${hook}" script to: ${truncate(cmd, 120)}`,
        { hook, from: bHooks[hook], to: cmd }));
    }
  }
  if (target.tarball && baseline.tarball) {
    if (target.tarball.hasBindingGyp && !baseline.tarball.hasBindingGyp) {
      out.push(finding('PD010', 'high',
        'Adds a binding.gyp. npm builds it during install even when package.json has no install script.', {}));
    }
    const before = new Set(baseline.tarball.nativeBinaries);
    const added = target.tarball.nativeBinaries.filter((p) => !before.has(p));
    if (added.length) {
      out.push(finding('PD011', 'medium', `Ships new compiled binaries: ${added.slice(0, 5).join(', ')}${added.length > 5 ? ', ...' : ''}`,
        { added }));
    }
  }
  return out;
}

// newDeps = [{ name, ageDays|null, missing, hasInstallHooks }]
export function dependencyFindings(newDeps, { youngDays = 30 } = {}) {
  const out = [];
  for (const d of newDeps) {
    if (d.missing) {
      out.push(finding('PD012', 'high', `Adds dependency "${d.name}", which does not exist on the registry.`, d));
    } else if (d.ageDays !== null && d.ageDays < youngDays) {
      const sev = d.hasInstallHooks ? 'high' : 'medium';
      out.push(finding('PD012', sev,
        `Adds dependency "${d.name}", a package first published ${Math.max(0, Math.round(d.ageDays))} day(s) ago` +
          (d.hasInstallHooks ? ' that runs an install script.' : '.'),
        d));
    } else {
      out.push(finding('PD012', 'low', `Adds dependency "${d.name}".`, d));
    }
  }
  return out;
}

// --- combination -------------------------------------------------------------------

// A changed release path is often a harmless CI refactor; new install-time code is
// often a harmless feature. Both at once is what the 2025-2026 worms looked like.
export function escalate(findings) {
  const pathHit = findings.find((f) => RULES[f.id].group === 'path' && sevRank(f.severity) >= sevRank('medium'));
  const payloadHit = findings.find((f) =>
    (f.id === 'PD009' || f.id === 'PD010') ||
    (f.id === 'PD012' && sevRank(f.severity) >= sevRank('high')));
  if (pathHit && payloadHit) {
    return [...findings, finding('PD100', 'critical',
      `Release path changed (${pathHit.rule}) and the release adds install-time code (${payloadHit.rule}). Treat as compromised until verified.`,
      { path: pathHit.id, payload: payloadHit.id })];
  }
  return findings;
}

function short(sha) {
  return sha ? sha.slice(0, 12) : 'unknown';
}

function truncate(s, n) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
