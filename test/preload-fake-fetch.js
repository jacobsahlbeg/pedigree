// Loaded with `node --import` by the Action integration test: swaps global fetch
// for the fake registry/GitHub described in $PEDIGREE_FAKE_WORLD, and writes the
// world back on exit so the test can inspect side effects (PR comments).

import { readFileSync, writeFileSync } from 'node:fs';
import { fakeFetch } from './world.js';

const path = process.env.PEDIGREE_FAKE_WORLD;
const world = JSON.parse(readFileSync(path, 'utf8'));
globalThis.fetch = fakeFetch(world);
process.on('exit', () => writeFileSync(path, JSON.stringify(world)));
