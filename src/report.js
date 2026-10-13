// Output formats: terminal text, GitHub-flavored Markdown (job summary / PR comment), JSON.

import { RULES, SEVERITIES, sevRank } from './rules.js';

const ICON = { critical: '🛑', high: '🔴', medium: '🟠', low: '🟡', info: '⚪' };
export const COMMENT_MARKER = '<!-- pedigree-report -->';

export function overallSeverity(reports) {
  let max = 'info';
  for (const r of reports) if (sevRank(r.maxSeverity) > sevRank(max)) max = r.maxSeverity;
  return max;
}

export function shouldFail(reports, failOn) {
  if (!failOn || failOn === 'none') return false;
  if (!SEVERITIES.includes(failOn)) throw new Error(`fail-on must be one of: none, ${SEVERITIES.join(', ')}`);
  return reports.some((r) => sevRank(r.maxSeverity) >= sevRank(failOn));
}

function visible(findings, minSeverity) {
  return findings.filter((f) => sevRank(f.severity) >= sevRank(minSeverity));
}

export function toText(reports, { minSeverity = 'low', skipped = 0 } = {}) {
  const lines = [];
  for (const r of reports) {
    const head = `${r.name}@${r.version}${r.baseline ? `  (compared with ${r.baseline})` : ''}`;
    if (r.error) {
      lines.push(`? ${head}\n    could not analyze: ${r.error}`);
      continue;
    }
    const shown = visible(r.findings, minSeverity);
    if (!shown.length) {
      lines.push(`✓ ${head}`);
      continue;
    }
    lines.push(`${r.maxSeverity.toUpperCase().padEnd(8)} ${head}`);
    for (const f of shown) lines.push(`    [${f.severity}] ${f.id} ${f.rule}: ${f.message}`);
  }
  if (skipped) lines.push(`… ${skipped} more change(s) not analyzed (raise max-packages to include them).`);
  return lines.join('\n');
}

export function toMarkdown(reports, { minSeverity = 'low', skipped = 0, failOn = 'high', title = 'Pedigree: dependency release check' } = {}) {
  const flagged = reports.filter((r) => r.error || visible(r.findings, minSeverity).length);
  const clean = reports.length - flagged.length;
  const overall = overallSeverity(reports);
  const fail = shouldFail(reports, failOn);

  const out = [COMMENT_MARKER, `## ${title}`, ''];
  if (!reports.length) {
    out.push('No registry dependency versions changed.');
    return out.join('\n');
  }
  out.push(
    fail
      ? `${ICON[overall]} **${flagged.length} of ${reports.length} upgraded package(s) need review.** Highest severity: **${overall}** (fails at ${failOn}).`
      : `✅ Checked ${reports.length} upgraded package(s). ${flagged.length ? `${flagged.length} have notes below, none at or above **${failOn}**.` : 'Each release matches its own history.'}`,
    '',
  );

  if (flagged.length) {
    out.push('| | Package | Compared with | Findings |', '|---|---|---|---|');
    for (const r of sortReports(flagged)) {
      const f = visible(r.findings, minSeverity);
      const cell = r.error ? `could not analyze: ${esc(r.error)}` : f.map((x) => `\`${x.id}\` ${esc(x.rule)}`).join('<br>');
      out.push(`| ${r.error ? '❔' : ICON[r.maxSeverity]} | \`${r.name}@${r.version}\` | ${r.baseline ? `\`${r.baseline}\`` : '-'} | ${cell} |`);
    }
    out.push('');
    out.push('<details><summary>Details</summary>', '');
    for (const r of sortReports(flagged)) {
      out.push(`#### ${r.error ? '❔' : ICON[r.maxSeverity]} ${r.name}@${r.version}`);
      if (r.provenance) {
        out.push(`Built from \`${r.provenance.repository}\` by \`${r.provenance.workflow}\` on \`${r.provenance.event}\`` +
          (r.provenance.commit ? ` at \`${r.provenance.commit.slice(0, 12)}\`` : '') + '.');
      } else if (!r.error) {
        out.push('No build provenance.');
      }
      for (const f of visible(r.findings, minSeverity)) out.push(`- **${f.severity}** \`${f.id}\` ${esc(f.message)}`);
      out.push('');
    }
    out.push('</details>', '');
  }
  if (clean) out.push(`${clean} other upgrade(s) matched their release history.`);
  if (skipped) out.push(`${skipped} more change(s) were not analyzed (raise \`max-packages\`).`);
  out.push('', '<sub>Rules: ' + Object.entries(RULES).filter(([, r]) => r.group !== 'context').map(([id, r]) => `${id} ${r.name}`).join(' · ') + '</sub>');
  return out.join('\n');
}

export function toJson(reports, extra = {}) {
  return JSON.stringify({ tool: 'pedigree-check', version: '0.1.0', overall: overallSeverity(reports), ...extra, reports }, null, 2);
}

function sortReports(reports) {
  return [...reports].sort((a, b) => sevRank(b.maxSeverity) - sevRank(a.maxSeverity) || a.name.localeCompare(b.name));
}

function esc(s) {
  return String(s).replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/\r?\n/g, ' ');
}
