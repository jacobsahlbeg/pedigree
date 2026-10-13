// Optional config file (default .github/pedigree.json):
//
// {
//   "ignore": [
//     { "package": "some-pkg", "rule": "PD004", "reason": "moved release workflow in v3" },
//     { "package": "other-pkg", "version": "2.1.0", "rule": "*", "reason": "reviewed manually" }
//   ]
// }
//
// Ignores require a reason so the decision stays reviewable in the repo history.

import { readFileSync, existsSync } from 'node:fs';
import { maxSeverity, RULES } from './rules.js';

export function loadConfig(path) {
  if (!path || !existsSync(path)) return { ignore: [] };
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  return validateConfig(raw, path);
}

export function validateConfig(raw, source = 'config') {
  const ignore = Array.isArray(raw?.ignore) ? raw.ignore : [];
  ignore.forEach((rule, i) => {
    if (!rule || typeof rule.package !== 'string') throw new Error(`${source}: ignore[${i}] needs a "package"`);
    if (typeof rule.rule !== 'string' || (rule.rule !== '*' && !RULES[rule.rule])) {
      throw new Error(`${source}: ignore[${i}] needs a "rule" (a rule id like PD004, or "*")`);
    }
    if (typeof rule.reason !== 'string' || !rule.reason.trim()) throw new Error(`${source}: ignore[${i}] needs a "reason"`);
  });
  return { ignore };
}

export function applyIgnores(reports, config) {
  if (!config?.ignore?.length) return reports;
  return reports.map((r) => {
    const kept = r.findings.filter(
      (f) =>
        !config.ignore.some(
          (ig) =>
            ig.package === r.name &&
            (!ig.version || ig.version === r.version) &&
            (ig.rule === '*' || ig.rule === f.id),
        ),
    );
    if (kept.length === r.findings.length) return r;
    return { ...r, findings: kept, maxSeverity: maxSeverity(kept), ignored: r.findings.length - kept.length };
  });
}
