import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as Record<string, unknown>;

/**
 * Fields copied verbatim from the root manifest. Deriving them rather than
 * restating them keeps the published metadata from drifting out of sync.
 */
const inherited = [
  'name',
  'version',
  'description',
  'homepage',
  'bugs',
  'license',
  'author',
  'keywords',
  'repository',
  'type',
  'sideEffects',
  'engines',
] as const;

// Paths are bare because the manifest is written into dist/ and published from there.
const published = {
  ...Object.fromEntries(inherited.map((key) => [key, manifest[key]])),
  exports: {
    '.': {
      types: './index.d.ts',
      import: './index.js',
    },
  },
  publishConfig: {
    access: 'public',
  },
};

await mkdir(dist, { recursive: true });
await writeFile(join(dist, 'package.json'), `${JSON.stringify(published, null, 2)}\n`);

await copyFile(join(root, 'README.md'), join(dist, 'README.md'));
await copyFile(join(root, 'LICENSE'), join(dist, 'LICENSE'));
