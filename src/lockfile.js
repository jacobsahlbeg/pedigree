// Lockfile parsing and diffing for npm (v1/v2/v3), pnpm (v5-v9) and yarn (v1 + berry).
// We only need the set of registry packages: name -> versions.

export const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

export function detectKind(filename, text) {
  const base = (filename || '').split('/').pop();
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'npm';
  if (base === 'pnpm-lock.yaml') return 'pnpm';
  if (base === 'yarn.lock') return text.includes('__metadata:') ? 'yarn-berry' : 'yarn-v1';
  const t = text.trimStart();
  if (t.startsWith('{')) return 'npm';
  if (/^lockfileVersion:/m.test(text)) return 'pnpm';
  if (text.includes('__metadata:')) return 'yarn-berry';
  if (text.includes('# yarn lockfile v1')) return 'yarn-v1';
  throw new Error(`Cannot tell what kind of lockfile ${filename || 'this'} is`);
}

// Returns Map<name, Set<version>> of registry-sourced packages.
export function parseLockfile(filename, text) {
  const kind = detectKind(filename, text);
  const out = new Map();
  const add = (name, version) => {
    if (!name || !version || !isRegistryVersion(version)) return;
    if (!out.has(name)) out.set(name, new Set());
    out.get(name).add(version);
  };
  switch (kind) {
    case 'npm':
      parseNpm(JSON.parse(text), add);
      break;
    case 'pnpm':
      parsePnpm(text, add);
      break;
    case 'yarn-v1':
      parseYarnV1(text, add);
      break;
    case 'yarn-berry':
      parseYarnBerry(text, add);
      break;
  }
  return out;
}

function isRegistryVersion(v) {
  // Plain semver only: skips git/file/link/workspace specifiers.
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(v);
}

function nameFromNodeModulesPath(path) {
  const idx = path.lastIndexOf('node_modules/');
  return idx === -1 ? null : path.slice(idx + 'node_modules/'.length);
}

function looksLikeRegistry(resolved) {
  if (!resolved) return true; // bundled or older lockfiles omit it
  return /^https?:\/\/[^/]*registry/i.test(resolved) || resolved.includes('/-/');
}

function parseNpm(lock, add) {
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.link || entry.inBundle) continue;
      if (!looksLikeRegistry(entry.resolved)) continue;
      const name = entry.name || nameFromNodeModulesPath(path);
      add(name, entry.version);
    }
    return;
  }
  // lockfileVersion 1: nested "dependencies".
  const walk = (deps) => {
    for (const [name, entry] of Object.entries(deps || {})) {
      if (entry.bundled || !looksLikeRegistry(entry.resolved)) {
        walk(entry.dependencies);
        continue;
      }
      add(name, entry.version);
      walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
}

function parsePnpm(text, add) {
  const lines = text.split(/\r?\n/);
  let inPackages = false;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      inPackages = line.startsWith('packages:');
      continue;
    }
    if (!inPackages) continue;
    // Keys sit at exactly two spaces of indentation.
    const m = /^ {2}(?! )['"]?([^'":]+?)['"]?:\s*$/.exec(line) || /^ {2}(?! )['"]?([^'":]+?)['"]?:\s/.exec(line);
    if (!m) continue;
    const key = m[1].trim().replace(/^\//, '');
    // pnpm v5: name/1.2.3 or @scope/name/1.2.3, peers after "_"
    const v5 = /^((?:@[^/]+\/)?[^/@]+)\/(\d+\.\d+\.\d+[^_(/]*)(?:[_(].*)?$/.exec(key);
    // pnpm v6+: name@1.2.3 or @scope/name@1.2.3, peers in "(...)"
    const v6 = /^((?:@[^/]+\/)?[^/@]+)@(\d+\.\d+\.\d+[^_(]*)(?:[_(].*)?$/.exec(key);
    const hit = v6 || v5;
    if (hit) add(hit[1], hit[2]);
  }
}

function parseYarnV1(text, add) {
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const lines = block.split('\n');
    const header = lines[0];
    if (!header || header.startsWith('#') || !header.endsWith(':')) continue;
    const first = header.slice(0, -1).split(',')[0].trim().replace(/^"|"$/g, '');
    const at = first.lastIndexOf('@');
    if (at <= 0) continue;
    const name = first.slice(0, at);
    const version = /^\s+version "([^"]+)"/m.exec(block)?.[1];
    const resolved = /^\s+resolved "([^"]+)"/m.exec(block)?.[1];
    if (resolved && !/registry\.(yarnpkg|npmjs)\.(com|org)/.test(resolved) && !resolved.includes('/-/')) continue;
    add(name, version);
  }
}

function parseYarnBerry(text, add) {
  for (const m of text.matchAll(/^ {2}resolution: "?(.+?)"?\s*$/gm)) {
    const res = m[1];
    const idx = res.indexOf('@npm:');
    if (idx <= 0) continue; // workspace:, patch:, git, file: etc.
    add(res.slice(0, idx), res.slice(idx + 5));
  }
}

// Packages whose version set changed between two lockfiles.
// Returns [{ name, version, previous: [versions] }] for every newly introduced name@version.
export function diffLockfiles(base, head) {
  const changes = [];
  for (const [name, versions] of head) {
    const before = base.get(name) || new Set();
    for (const version of versions) {
      if (!before.has(version)) {
        changes.push({ name, version, previous: [...before].sort() });
      }
    }
  }
  changes.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return changes;
}
