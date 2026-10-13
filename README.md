# pedigree

**Checks that each npm dependency upgrade was released the way that package is normally released.**

In 2026, npm worms started publishing malicious versions that carry valid, signed SLSA provenance (TanStack in May, the Red Hat packages in June, ChainDrop in August). Provenance proves *which pipeline* built a package. It does not prove that the pipeline only ran code the maintainers reviewed. An orphan commit pushed from a stolen account, or an old workflow that still has publishing rights, produces a perfectly valid attestation.

pedigree compares every new version in your lockfile against the package's own release history and flags the breaks:

- provenance that disappeared, or trusted publishing replaced by a personal token
- a different workflow file, trigger, branch, or source repository than recent releases used
- a source commit that is not part of the main branch, or that does not exist at all
- new install-time code: lifecycle scripts, `binding.gyp`, compiled binaries, brand-new dependencies

It runs as a GitHub Action on Dependabot and Renovate PRs, or as a CLI. It has **zero dependencies** and never executes package code.

## Quick start (GitHub Action)

```yaml
# .github/workflows/pedigree.yml
name: pedigree
on:
  pull_request:
    paths: ['**/package-lock.json', '**/npm-shrinkwrap.json', '**/pnpm-lock.yaml', '**/yarn.lock']

permissions:
  contents: read
  pull-requests: write   # only needed for comment: true

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jacobsahlbeg/pedigree@v0.1.0   # pin to a commit SHA in production
        with:
          fail-on: high
          comment: true
```

Use `pull_request`, not `pull_request_target`. The check only reads public data, and the Action warns if it is run under `pull_request_target`.

Results appear in the job summary, as annotations on the lockfile, as outputs (`max-severity`, `flagged-count`, `report-path`), and optionally as a PR comment that updates in place.

## CLI

```bash
# check specific releases
node bin/pedigree.js check @tanstack/react-router@1.170.44 axios@1.12.2

# check every version a lockfile change introduces
git show origin/main:package-lock.json > /tmp/base-lock.json
node bin/pedigree.js diff /tmp/base-lock.json package-lock.json

# options: --json, --fail-on <severity>, --show <severity>, --baseline <version>,
#          --gap-hours <n>, --no-tarballs, --no-github, --config <path>
```

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to enable the source-history checks (PD007, PD008). Everything else uses only the public npm registry.

Lockfiles: npm (v1, v2, v3), pnpm (v5 through v9), and yarn (v1 and berry).

## Rules

| ID | Default severity | Flags | Real-world pattern |
|---|---|---|---|
| PD001 provenance-dropped | high | Earlier releases had provenance, this one has none | Publishing with a stolen npm token |
| PD002 publish-method-changed | high / medium | Trusted publishing replaced by a token, or a new trusted-publisher config | Account takeover (axios 1.14.0 used trusted publishing; the malicious 1.14.1 came 3 days later) |
| PD003 source-repo-changed | high (low if the GitHub repo ID is unchanged) | Built from a different repository | Lookalike or hijacked repos |
| PD004 workflow-changed | high | Built by a workflow file recent releases did not use | Dormant workflow with publish rights (TanStack, May 2026) |
| PD005 trigger-changed | high for `pull_request_target`, `issue_comment`, `workflow_run`, ... / medium otherwise | Release run started by a different kind of event | Cache poisoning via `pull_request_target` (TanStack) |
| PD006 ref-changed | medium | Built from a different branch, or branch instead of tag | Throwaway attacker branches |
| PD007 commit-off-main | critical if orphan or nonexistent / high otherwise | Source commit is not in the default branch history | Orphan commits from compromised accounts (Red Hat, June 2026) |
| PD008 no-merged-pr | medium | Commit not linked to a merged PR, unlike recent releases | Direct pushes from stolen credentials |
| PD009 install-script-added | high (medium if changed) | New `preinstall`, `install`, or `postinstall` | Shai-Hulud family |
| PD010 native-build-added | high | New `binding.gyp` (npm builds it on install with no script) | Miasma wave 2 (June 2026) |
| PD011 native-binary-added | medium | New `.node`, `.so`, `.dll`, `.dylib`, `.exe` files | Bundled stealers |
| PD012 new-dependency | high if days-old with an install script / medium if days-old / low | New runtime dependency | `plain-crypto-js` in axios |
| PD017 version-missing | high | The version is no longer on the registry | Versions removed for being malicious |
| PD100 path-and-payload-changed | critical | Release path changed **and** new install-time code | Every worm wave above |

Context notes (info and low): PD013 publisher-changed, PD014 fresh-release (under 24h old), PD015 no-baseline, PD016 lineage-unchecked.

## How the comparison works

1. **Baseline.** pedigree picks the closest earlier release that is at least 72 hours older than the target. Worms publish several malicious versions within hours, so a "settled" baseline sits outside the burst. It searches the same minor line first (so a backport like `19.0.8` compares with `19.0.7`), then the same major line, then everything, choosing the nearest lower version.
2. **History.** The baseline plus up to four more settled releases form the package's known release paths. A workflow, trigger, branch, or publisher that any of them used is not new. This keeps projects that alternate between tag pushes and manual dispatches quiet.
3. **Facts.** For the target and baseline: provenance (SLSA v1 and v0.2), how it was published (`_npmUser.trustedPublisher`), the packed `package.json` scripts, and a file listing of the tarball. Tarballs are listed in memory and never written to disk or executed.
4. **Lineage.** With a GitHub token: is the provenance commit an ancestor of the default branch (compare API), is it an orphan or missing, and did it come from a merged PR. Results are judged relative to the baseline, so projects that always release from maintenance branches or always push release commits directly are not flagged.
5. **Combination.** A path change alone is often a CI refactor. New install-time code alone is often a feature. Both together escalates to critical (PD100).

## Real-world noise check

`scripts/eval-real-world.js` runs pedigree against the 3 most recent stable releases of 80 popular packages (240 releases, 141 with provenance). Results from October 13, 2026, registry checks only (no GitHub token was available in the test environment):

| Outcome | Releases |
|---|---|
| Clean or info only | 199 (83%) |
| Low notes only | 23 |
| Medium (shown, does not fail by default) | 14 |
| High (fails at the default `fail-on: high`) | 4 (1.7%) |

The 4 high results were all genuine release-process changes, not parsing errors: `prisma@7.10.0` was published by a bot token without provenance after five consecutive trusted-publishing releases, `@prisma/client@7.10.0` moved to a new workflow and branch, and two `@anthropic-ai/sdk` releases moved to a new workflow and trigger. Each is the kind of change a reviewer should look at once, then record in the ignore file. Full output: `eval/results.json`.

Building this check changed the tool: the first run flagged 47 releases at medium or above. Three fixes cut that to 18: normalizing npm's September 2026 change to trusted-publisher ID format, recognizing repository transfers by GitHub's numeric repository ID (React moved from `facebook/react` to `react/react`), and comparing against a window of recent releases rather than a single one.

## Handling a finding

After checking a flagged release (release notes, the workflow run linked in the report, the maintainers' announcements), record the decision in `.github/pedigree.json`. A reason is required so the decision stays reviewable in your history:

```json
{
  "ignore": [
    { "package": "@prisma/client", "version": "7.10.0", "rule": "*", "reason": "release workflow migration announced in prisma/prisma#12345" },
    { "package": "koa", "rule": "PD005", "reason": "koa releases by manual dispatch since 3.2.1" }
  ]
}
```

## Limitations

- **npm only** for now. PyPI (PEP 740 attestations) is the natural next ecosystem.
- **Signatures are not verified here.** pedigree reads the provenance claims the registry serves. Run `npm audit signatures` for cryptographic verification; the two are complementary.
- **Same-path compromise is not a path change.** If malicious code is merged into `main` through a reviewed PR and released by the normal workflow, the release path looks normal. The payload rules (PD009 to PD012) still apply, but pedigree does not read code for malware.
- **The history window can hide reuse.** A workflow used by any of the last five settled releases counts as known. An attacker reusing one of those paths is not flagged by PD004 to PD006.
- **GitHub API limits.** Lineage checks cost a few API calls per package. Large lockfile refreshes can hit rate limits; pedigree then degrades to registry checks and says so (PD016).
- **Lineage checks are tested against a simulated GitHub API.** They have not yet been run against real repositories at scale.
- New packages and first releases have no baseline to compare against.

## Development

```bash
npm test                                  # 40 tests: attack scenarios, parsers, the Action end to end
node scripts/eval-real-world.js 3         # live noise check against the npm registry
```

`test/world.js` is a fake npm registry and GitHub API. The scenario tests replay the 2026 attack patterns (orphan commits, swapped workflows on `pull_request_target`, stolen tokens with a fresh dependency, `binding.gyp` payloads, publishing bursts) and the false-positive cases found in the real-world run.

## License

MIT
