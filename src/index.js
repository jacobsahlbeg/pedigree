// Public API.

import { createHttp } from './http.js';
import { Registry } from './registry.js';
import { GitHub } from './github.js';

export { analyzePackage, analyzeChanges, chooseBaseline, DEFAULTS } from './analyze.js';
export { parseLockfile, diffLockfiles, detectKind, LOCKFILE_NAMES } from './lockfile.js';
export { parseProvenance } from './provenance.js';
export { RULES, SEVERITIES } from './rules.js';
export { toText, toMarkdown, toJson, shouldFail, overallSeverity } from './report.js';
export { loadConfig, applyIgnores } from './config.js';
export { Registry, GitHub, createHttp };

export function createContext({ fetchImpl, githubToken = null, registryUrl, githubApi, options = {} } = {}) {
  const http = createHttp({ fetchImpl });
  return {
    registry: new Registry({ http, base: registryUrl }),
    github: githubToken ? new GitHub({ http, token: githubToken, apiBase: githubApi }) : null,
    options,
  };
}
