#!/usr/bin/env node
// False-positive check against real, legitimate releases.
//
//   node scripts/eval-real-world.js [releasesPerPackage=3] [out=eval/results.json]
//
// For each package below, analyzes its N most recent stable releases (each against
// its own automatic baseline) and tallies findings. Source-history (GitHub) checks
// run only when GITHUB_TOKEN/GH_TOKEN is set and the API is reachable.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createContext, analyzePackage } from '../src/index.js';
import { mapLimit } from '../src/analyze.js';
import { sevRank } from '../src/rules.js';

const PACKAGES = [
  'react', 'react-dom', 'vue', 'svelte', 'next', 'vite', 'esbuild', 'rollup', 'webpack', 'typescript',
  'eslint', 'prettier', '@babel/core', 'lodash', 'express', 'axios', 'zod', '@tanstack/react-query',
  '@tanstack/react-router', 'tailwindcss', 'postcss', 'jest', 'vitest', '@types/node', 'chalk',
  'commander', 'yargs', 'dotenv', 'uuid', 'date-fns', 'dayjs', 'ws', 'socket.io', 'mongoose', 'pg',
  'prisma', '@prisma/client', 'sharp', 'puppeteer', 'playwright', 'nx', 'turbo', 'pnpm', 'npm', 'semver',
  'glob', 'rimraf', 'fs-extra', 'debug', 'cors', 'jsonwebtoken', 'bcrypt', 'better-sqlite3', 'nodemon',
  'tsx', '@swc/core', 'storybook', '@angular/core', 'rxjs', '@reduxjs/toolkit', 'three', 'd3',
  'chart.js', 'sigstore', 'undici', 'got', 'hono', 'fastify', 'koa', '@nestjs/core', 'graphql',
  'openai', '@anthropic-ai/sdk', 'stripe', '@aws-sdk/client-s3', 'firebase', '@supabase/supabase-js',
  'pino', 'winston', 'msw',
];

const perPackage = Number(process.argv[2] || 3);
const outPath = process.argv[3] || 'eval/results.json';
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
const ctx = createContext({ githubToken: token });

const isStable = (v) => /^\d+\.\d+\.\d+$/.test(v);

const started = Date.now();
const targets = [];
for (const name of PACKAGES) {
  const p = await ctx.registry.packument(name).catch(() => null);
  if (!p) continue;
  const recent = Object.keys(p.versions)
    .filter(isStable)
    .sort((a, b) => Date.parse(p.time[b]) - Date.parse(p.time[a]))
    .slice(0, perPackage);
  for (const version of recent) targets.push({ name, version });
}

const reports = await mapLimit(targets, 6, (t) => analyzePackage(t, ctx));

const tally = { releases: reports.length, errors: 0, withProvenance: 0, bySeverity: {}, byRule: {} };
for (const r of reports) {
  if (r.error) tally.errors++;
  if (r.provenance) tally.withProvenance++;
  tally.bySeverity[r.maxSeverity] = (tally.bySeverity[r.maxSeverity] || 0) + 1;
  for (const f of r.findings) {
    const key = `${f.id} ${f.rule} (${f.severity})`;
    tally.byRule[key] = (tally.byRule[key] || 0) + 1;
  }
}
const atOrAbove = (s) => reports.filter((r) => sevRank(r.maxSeverity) >= sevRank(s)).length;
tally.wouldFailAtHigh = atOrAbove('high');
tally.wouldFailAtMedium = atOrAbove('medium');
tally.githubChecks = token ? 'attempted' : 'off (no token)';
tally.seconds = Math.round((Date.now() - started) / 1000);

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify({ generatedAt: new Date().toISOString(), tally, reports }, null, 2));

console.log(JSON.stringify(tally, null, 2));
console.log('\nReleases at medium or above:');
for (const r of reports.filter((x) => sevRank(x.maxSeverity) >= sevRank('medium'))) {
  console.log(`  ${r.maxSeverity.padEnd(8)} ${r.name}@${r.version} vs ${r.baseline}`);
  for (const f of r.findings.filter((x) => sevRank(x.severity) >= sevRank('medium'))) {
    console.log(`           ${f.id} ${f.message}`);
  }
}
