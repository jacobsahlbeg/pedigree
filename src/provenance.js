// Normalizes SLSA provenance (v1 and npm's older v0.2 format) into one shape:
//
//   { slsaVersion, repository, host, owner, repo, workflowPath, workflowRef,
//     ref: { kind, name }, eventName, commit, builderId, runUrl }
//
// Any field may be null when the statement does not carry it.

export function parseProvenance(statement) {
  if (!statement || typeof statement !== 'object') return null;
  const type = String(statement.predicateType || '');
  const pred = statement.predicate || {};
  if (type.includes('provenance/v1')) return fromV1(pred);
  if (type.includes('provenance/v0.2')) return fromV02(pred);
  return null;
}

function fromV1(pred) {
  const bd = pred.buildDefinition || {};
  const ext = bd.externalParameters || {};
  const internal = bd.internalParameters || {};
  const wf = ext.workflow || {};
  const deps = Array.isArray(bd.resolvedDependencies) ? bd.resolvedDependencies : [];
  const source = deps.find((d) => d?.digest?.gitCommit) || deps[0] || {};
  const fromUri = splitGitUri(source.uri);

  const repository = normalizeRepoUrl(wf.repository || ext.source || fromUri.repo);
  const workflowRef = wf.ref || fromUri.ref || null;
  return finish({
    slsaVersion: 'v1',
    repository,
    // Numeric GitHub IDs survive renames and org transfers; URLs do not.
    repositoryId: internal.github?.repository_id ? String(internal.github.repository_id) : null,
    ownerId: internal.github?.repository_owner_id ? String(internal.github.repository_owner_id) : null,
    workflowPath: wf.path || ext.entryPoint || null,
    workflowRef,
    eventName: internal.github?.event_name || internal.CI_PIPELINE_SOURCE || null,
    commit: source.digest?.gitCommit || source.digest?.sha1 || null,
    builderId: pred.runDetails?.builder?.id || null,
    runUrl: pred.runDetails?.metadata?.invocationId || null,
  });
}

function fromV02(pred) {
  const inv = pred.invocation || {};
  const cfg = inv.configSource || {};
  const env = inv.environment || {};
  const fromUri = splitGitUri(cfg.uri);
  const material = (pred.materials || []).find((m) => m?.digest?.sha1) || {};
  return finish({
    slsaVersion: 'v0.2',
    repository: normalizeRepoUrl(fromUri.repo || (env.GITHUB_REPOSITORY ? `https://github.com/${env.GITHUB_REPOSITORY}` : null)),
    repositoryId: env.GITHUB_REPOSITORY_ID ? String(env.GITHUB_REPOSITORY_ID) : null,
    ownerId: env.GITHUB_REPOSITORY_OWNER_ID ? String(env.GITHUB_REPOSITORY_OWNER_ID) : null,
    workflowPath: cfg.entryPoint || null,
    workflowRef: fromUri.ref || env.GITHUB_REF || null,
    eventName: env.GITHUB_EVENT_NAME || null,
    commit: cfg.digest?.sha1 || material.digest?.sha1 || env.GITHUB_SHA || null,
    builderId: pred.builder?.id || null,
    runUrl: env.GITHUB_RUN_ID && env.GITHUB_REPOSITORY
      ? `https://github.com/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
      : null,
  });
}

function finish(p) {
  const parsed = parseRepo(p.repository);
  return {
    ...p,
    host: parsed.host,
    owner: parsed.owner,
    repo: parsed.repo,
    ref: parseRef(p.workflowRef),
  };
}

// "git+https://github.com/o/r@refs/heads/main" -> { repo, ref }
export function splitGitUri(uri) {
  if (!uri || typeof uri !== 'string') return { repo: null, ref: null };
  const clean = uri.replace(/^git\+/, '');
  const at = clean.lastIndexOf('@refs/');
  if (at === -1) return { repo: clean, ref: null };
  return { repo: clean.slice(0, at), ref: clean.slice(at + 1) };
}

export function normalizeRepoUrl(url) {
  if (!url || typeof url !== 'string') return null;
  return url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
    .toLowerCase();
}

export function parseRepo(url) {
  if (!url) return { host: null, owner: null, repo: null };
  const m = /^https?:\/\/([^/]+)\/([^/]+)\/([^/#?]+)/.exec(url);
  if (!m) return { host: null, owner: null, repo: null };
  return { host: m[1], owner: m[2], repo: m[3] };
}

export function parseRef(ref) {
  if (!ref) return { kind: null, name: null };
  if (ref.startsWith('refs/heads/')) return { kind: 'branch', name: ref.slice(11) };
  if (ref.startsWith('refs/tags/')) return { kind: 'tag', name: ref.slice(10) };
  if (ref.startsWith('refs/pull/')) return { kind: 'pull', name: ref.slice(10) };
  return { kind: 'other', name: ref };
}

// Triggers that let code from outside the maintainers' reviewed history steer a run.
export const RISKY_EVENTS = new Set([
  'pull_request_target',
  'pull_request',
  'issue_comment',
  'issues',
  'workflow_run',
  'discussion',
  'discussion_comment',
  'fork',
  'watch',
]);
