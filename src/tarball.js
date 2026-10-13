// In-memory listing of npm tarballs (.tgz). Nothing is written to disk and
// nothing is executed: we only read tar headers and the package.json body.

import { gunzipSync } from 'node:zlib';

const BLOCK = 512;

export function listTarball(gz, { maxUnpackedBytes = 200 * 1024 * 1024 } = {}) {
  const tar = gunzipSync(gz, { maxOutputLength: maxUnpackedBytes });
  const files = [];
  let packageJson = null;
  let offset = 0;
  let paxPath = null;
  let longName = null;

  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);
    if (header.every((b) => b === 0)) break; // end-of-archive marker

    const size = parseOctal(header.subarray(124, 136));
    const type = String.fromCharCode(header[156] || 48); // '0' when NUL
    const name = cstr(header.subarray(0, 100));
    const prefix = isUstar(header) ? cstr(header.subarray(345, 500)) : '';
    const mode = parseOctal(header.subarray(100, 108));
    const bodyStart = offset + BLOCK;
    const body = tar.subarray(bodyStart, bodyStart + size);
    offset = bodyStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === 'x') {
      paxPath = parsePax(body).path ?? null;
      continue;
    }
    if (type === 'g') continue; // global pax header
    if (type === 'L') {
      longName = cstr(body);
      continue;
    }

    let full = paxPath || longName || (prefix ? `${prefix}/${name}` : name);
    paxPath = null;
    longName = null;

    // npm tarballs wrap everything in a top-level folder (normally "package/").
    full = full.replace(/^\.?\/?[^/]+\//, '');
    if (!full) continue;

    if (type === '0' || type === '\0' || type === '7') {
      files.push({ path: full, size, mode });
      if (full === 'package.json' && packageJson === null) {
        try {
          packageJson = JSON.parse(body.toString('utf8'));
        } catch {
          packageJson = undefined; // present but unparseable
        }
      }
    } else if (type === '2' || type === '1') {
      files.push({ path: full, size: 0, mode, link: true });
    }
  }
  return { files, packageJson: packageJson ?? null };
}

function cstr(buf) {
  const end = buf.indexOf(0);
  return buf.subarray(0, end === -1 ? buf.length : end).toString('utf8');
}

function parseOctal(buf) {
  // GNU base-256 encoding for very large sizes.
  if (buf[0] & 0x80) {
    let n = 0;
    for (let i = 1; i < buf.length; i++) n = n * 256 + buf[i];
    return n;
  }
  const s = cstr(buf).trim();
  return s ? parseInt(s, 8) || 0 : 0;
}

function isUstar(header) {
  return header.subarray(257, 262).toString('latin1') === 'ustar';
}

function parsePax(body) {
  const out = {};
  let i = 0;
  const text = body.toString('utf8');
  while (i < text.length) {
    const sp = text.indexOf(' ', i);
    if (sp === -1) break;
    const len = parseInt(text.slice(i, sp), 10);
    if (!len) break;
    const record = text.slice(sp + 1, i + len - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    i += len;
  }
  return out;
}

const NATIVE_EXT = /\.(node|so|dylib|dll|exe)$/i;

// Facts pedigree compares between two releases.
export function summarizeTarball(listing) {
  const paths = new Set(listing.files.map((f) => f.path));
  return {
    fileCount: listing.files.length,
    hasBindingGyp: [...paths].some((p) => p === 'binding.gyp' || p.endsWith('/binding.gyp')),
    nativeBinaries: [...paths].filter((p) => NATIVE_EXT.test(p)).sort(),
    packageJson: listing.packageJson,
  };
}
