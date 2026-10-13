// npm registry client: packuments, provenance attestations, and tarballs.
// Read-only. Nothing fetched here is ever executed.

const DEFAULT_REGISTRY = 'https://registry.npmjs.org';

export function encodeName(name) {
  // Scoped packages are addressed as @scope%2fname.
  return name.startsWith('@') ? name.replace('/', '%2f') : encodeURIComponent(name);
}

export class Registry {
  constructor({ http, base = DEFAULT_REGISTRY } = {}) {
    if (!http) throw new Error('Registry needs an http client');
    this.http = http;
    this.base = base.replace(/\/$/, '');
    this.packuments = new Map();
    this.attestationCache = new Map();
  }

  // Full packument: per-version manifests plus the publish-time map.
  async packument(name) {
    if (!this.packuments.has(name)) {
      const p = this.http
        .json(`${this.base}/${encodeName(name)}`)
        .then((r) => r.data);
      this.packuments.set(name, p);
    }
    return this.packuments.get(name);
  }

  // Returns { provenance, publish } decoded in-toto statements, or nulls when absent.
  // Note: this reads the attestation claims. Cryptographic verification of the
  // Sigstore bundle is what `npm audit signatures` does; pedigree checks what the
  // (already registry-verified) claims say against the package's history.
  async attestations(name, version) {
    const key = `${name}@${version}`;
    if (!this.attestationCache.has(key)) {
      const p = this.http
        .json(`${this.base}/-/npm/v1/attestations/${encodeName(name)}@${encodeURIComponent(version)}`)
        .then((r) => decodeAttestations(r.data));
      this.attestationCache.set(key, p);
    }
    return this.attestationCache.get(key);
  }

  async tarball(url, maxBytes) {
    return this.http.bytes(url, { maxBytes });
  }
}

export function decodeAttestations(body) {
  const out = { provenance: null, publish: null };
  if (!body || !Array.isArray(body.attestations)) return out;
  for (const att of body.attestations) {
    const payload = att?.bundle?.dsseEnvelope?.payload;
    if (!payload) continue;
    let stmt;
    try {
      stmt = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    } catch {
      continue;
    }
    const type = String(stmt.predicateType || att.predicateType || '');
    if (type.includes('slsa.dev/provenance')) out.provenance = stmt;
    else if (type.includes('npm/attestation') && type.includes('publish')) out.publish = stmt;
  }
  return out;
}
