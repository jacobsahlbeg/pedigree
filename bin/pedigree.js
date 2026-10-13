#!/usr/bin/env node
// pedigree CLI
//
//   pedigree check <name>@<version> [...more]   check specific releases
//   pedigree diff <base-lockfile> <head-lockfile>  check every version a lockfile change introduces
//
// Options:
//   --json                 print JSON instead of text
//   --fail-on <severity>   exit 1 at or above this severity (default: high; "none" to never fail)
//   --show <severity>      lowest severity to print (default: low)
//   --baseline <version>   compare against this version instead of the automatic baseline (check only)
//   --gap-hours <n>        how old a release must be to serve as baseline (default: 72)
//   --no-tarballs          skip downloading tarballs (no binding.gyp / binary checks)
//   --no-github            skip source-history checks even if a token is set
//   --config <path>        ignore file (default: .github/pedigree.json if present)
//
// Source-history checks use GITHUB_TOKEN or GH_TOKEN when set.

import { readFileSync } from 'node:fs';
import {
  createContext,
  analyzePackage,
  analyzeChanges,
  parseLockfile,
  diffLockfiles,
  toText,
  toJson,
  shouldFail,
  loadConfig,
  applyIgnores,
} from '../src/index.js';

function parseArgs(argv) {
  const args = { _: [], json: false, failOn: 'high', show: 'low', tarballs: true, github: true, config: '.github/pedigree.json' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--json') args.json = true;
    else if (a === '--fail-on') args.failOn = next();
    else if (a === '--show') args.show = next();
    else if (a === '--baseline') args.baseline = next();
    else if (a === '--gap-hours') args.gapHours = Number(next());
    else if (a === '--no-tarballs') args.tarballs = false;
    else if (a === '--no-github') args.github = false;
    else if (a === '--config') args.config = next();
    else if (a === '-h' || a === '--help') args.help = true;
    else if (a.startsWith('--')) throw new Error(`Unknown option ${a}`);
    else args._.push(a);
  }
  return args;
}

function splitSpec(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) throw new Error(`Expected <name>@<version>, got "${spec}"`);
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

const HELP = readFileSync(new URL(import.meta.url), 'utf8')
  .split('\n')
  .filter((l) => l.startsWith('//'))
  .map((l) => l.replace(/^\/\/ ?/, ''))
  .join('\n');

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [cmd, ...rest] = args._;
  if (args.help || !cmd) {
    console.log(HELP);
    return 0;
  }

  const token = args.github ? process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null : null;
  const options = { inspectTarballs: args.tarballs };
  if (args.gapHours) options.baselineGapHours = args.gapHours;
  const ctx = createContext({ githubToken: token, options });
  const config = loadConfig(args.config);

  let reports;
  let skipped = 0;
  if (cmd === 'check') {
    if (!rest.length) throw new Error('check needs at least one <name>@<version>');
    if (args.baseline && rest.length > 1) throw new Error('--baseline only works with a single package');
    reports = [];
    for (const spec of rest) {
      const { name, version } = splitSpec(spec);
      reports.push(await analyzePackage({ name, version }, { ...ctx, options: { ...options, baseline: args.baseline } }));
    }
  } else if (cmd === 'diff') {
    if (rest.length !== 2) throw new Error('diff needs <base-lockfile> <head-lockfile>');
    const [basePath, headPath] = rest;
    const base = parseLockfile(basePath, readFileSync(basePath, 'utf8'));
    const head = parseLockfile(headPath, readFileSync(headPath, 'utf8'));
    const changes = diffLockfiles(base, head);
    ({ reports, skipped } = await analyzeChanges(changes, ctx));
  } else {
    throw new Error(`Unknown command "${cmd}". Try --help.`);
  }

  reports = applyIgnores(reports, config);
  console.log(args.json ? toJson(reports, { skipped }) : toText(reports, { minSeverity: args.show, skipped }));
  return shouldFail(reports, args.failOn) ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`pedigree: ${err.message}`);
    process.exit(2);
  },
);
