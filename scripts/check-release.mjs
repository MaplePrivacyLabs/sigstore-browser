// Verify release metadata before rebuilding the recorded source revision.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: 'inherit' });
const root = resolve(import.meta.dirname, '..');
const read = (file) => JSON.parse(readFileSync(join(root, file), 'utf8'));
const release = read('release.json');
const sha = /^[a-f0-9]{40}$/;
if (!sha.test(release.source)) throw new Error('Expected a full source commit');
if (release.node !== '26.13.1' || release.typescript !== '6.0.3') {
  throw new Error('Unexpected release toolchain');
}
if (process.versions.node !== release.node) throw new Error(`Use Node ${release.node}`);
const source = (file) => JSON.parse(execFileSync('git', ['show', `${release.source}:${file}`], { cwd: root, encoding: 'utf8' }));
const expected = source('package.json');
const expectedLock = source('package-lock.json');
delete expected.scripts.prepare;
let tufSource;
let tufManifest;
if (expected.name === '@freedomofpress/sigstore-browser') {
  if (!sha.test(release.tufRelease)) throw new Error('Expected a full TUF release commit');
  const dependency = '@freedomofpress/tuf-browser';
  const pinned = /^git\+(https:\/\/[^#]+\.git)#([a-f0-9]{40})$/.exec(expected.dependencies[dependency]);
  if (!pinned) throw new Error('Source must pin an exact TUF Git commit');
  tufSource = { url: pinned[1], commit: pinned[2] };
  const spec = `git+https://github.com:443/MaplePrivacyLabs/tuf-browser.git#${release.tufRelease}`;
  expected.dependencies[dependency] = spec;
  expectedLock.packages[''].dependencies[dependency] = spec;
  const locked = expectedLock.packages[`node_modules/${dependency}`];
  locked.resolved = spec;
  // Git is pinned by its commit. npm ignores archive integrity for Git installs.
  delete locked.integrity;
} else if (expected.name !== '@freedomofpress/tuf-browser') {
  throw new Error('Unexpected package');
}
if (expected.devDependencies.typescript !== release.typescript) throw new Error('Compiler pin mismatch');
for (const hook of ['prepare', 'preinstall', 'install', 'postinstall']) {
  if (Object.hasOwn(read('package.json').scripts, hook)) throw new Error(`Forbidden release hook: ${hook}`);
}
for (const [file, value] of [['package.json', expected], ['package-lock.json', expectedLock]]) {
  if (!isDeepStrictEqual(read(file), value)) throw new Error(`${file} differs from the source release transformation`);
}
// Entry-point code, build configuration and any additional tracked consumption
// files must match the source too. Only these generated release files may differ.
run('git', ['diff', '--exit-code', release.source, '--', '.', ':!dist', ':!package.json', ':!package-lock.json', ':!release.json'], root);
const scratch = mkdtempSync(join(tmpdir(), 'release-check-'));
try {
  const archive = join(scratch, 'source.tar');
  run('git', ['archive', '--output', archive, release.source], root);
  run('tar', ['-xf', archive, '-C', scratch], root);
  rmSync(archive);
  for (const file of ['package.json', 'package-lock.json']) {
    copyFileSync(join(root, file), join(scratch, file));
  }
  if (tufSource) {
    // The release pointer is not evidence of its contents: independently build
    // the source dependency pinned by the recorded browser source revision.
    const repository = join(scratch, 'tuf-repository');
    mkdirSync(repository);
    run('git', ['init', '--quiet'], repository);
    run('git', ['fetch', '--quiet', '--no-tags', tufSource.url,
      tufSource.commit, release.tufRelease], repository);
    const provenance = JSON.parse(execFileSync('git',
      ['show', `${release.tufRelease}:release.json`], { cwd: repository, encoding: 'utf8' }));
    if (provenance.source !== tufSource.commit) {
      throw new Error('TUF release source does not match the browser source dependency pin');
    }
    const extract = (revision, destination, paths = []) => {
      mkdirSync(destination);
      const tar = join(scratch, 'tuf.tar');
      run('git', ['archive', '--output', tar, revision, ...paths], repository);
      run('tar', ['-xf', tar, '-C', destination], repository);
      rmSync(tar);
    };
    const sourceTree = join(scratch, 'tuf-source');
    const releaseTree = join(scratch, 'tuf-release');
    extract(tufSource.commit, sourceTree);
    extract(release.tufRelease, releaseTree);
    tufManifest = JSON.parse(readFileSync(join(sourceTree, 'package.json'), 'utf8'));
    delete tufManifest.scripts.prepare;
    const shippedManifest = JSON.parse(readFileSync(join(releaseTree, 'package.json'), 'utf8'));
    if (!isDeepStrictEqual(shippedManifest, tufManifest)) {
      throw new Error('TUF release manifest differs from its pinned source transformation');
    }
    const lock = (tree) => JSON.parse(readFileSync(join(tree, 'package-lock.json'), 'utf8'));
    if (!isDeepStrictEqual(lock(sourceTree), lock(releaseTree))) {
      throw new Error('TUF release lockfile differs from its pinned source');
    }
    run('git', ['diff', '--exit-code', tufSource.commit, release.tufRelease,
      '--', '.', ':!dist', ':!package.json', ':!package-lock.json', ':!release.json'], repository);
    run('npm', ['ci', '--ignore-scripts'], sourceTree);
    run('npm', ['run', 'build'], sourceTree);
    run('diff', ['-r', join(sourceTree, 'dist'), join(releaseTree, 'dist')], root);
  }
  run('npm', ['ci', '--ignore-scripts'], scratch);
  if (tufSource) {
    const installed = JSON.parse(readFileSync(join(scratch, 'node_modules',
      '@freedomofpress', 'tuf-browser', 'package.json'), 'utf8'));
    if (!isDeepStrictEqual(installed, tufManifest)) {
      throw new Error('Installed TUF manifest differs from its pinned source transformation');
    }
    run('diff', ['-r', join(scratch, 'tuf-source', 'dist'),
      join(scratch, 'node_modules', '@freedomofpress', 'tuf-browser', 'dist')], root);
  }
  run('npm', ['run', 'build'], scratch);
  run('diff', ['-r', join(root, 'dist'), join(scratch, 'dist')], root);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
