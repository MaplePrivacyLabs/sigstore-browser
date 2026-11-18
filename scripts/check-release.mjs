// Checks that this prebuilt release is exactly what its recorded source revision builds to.
//
// release.json names the source commit, the toolchain and the prebuilt TUF release commit. The check
// derives the expected package.json and lockfile from the source, requires every other tracked file
// to match the source, independently rebuilds the TUF source that the browser source pins and
// compares it with the TUF release and with what npm installs, and finally rebuilds this package and
// compares its dist/ byte for byte.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { preparationScripts, releaseManifest } from "./release-policy.mjs";

const NODE = "26.13.1";
const TYPESCRIPT = "6.0.3";
const TUF_PACKAGE = "@freedomofpress/tuf-browser";
const TUF_RELEASE_URL = "https://github.com:443/MaplePrivacyLabs/tuf-browser.git";
const FULL_COMMIT = /^[a-f0-9]{40}$/;
// Files a release generates from its source; every other tracked file must equal the source.
const GENERATED = [":!dist", ":!package.json", ":!package-lock.json", ":!release.json"];

const root = resolve(import.meta.dirname, "..");

const run = (command, args, cwd) => execFileSync(command, args, { cwd, stdio: "inherit" });
const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
const showJson = (cwd, revision, file) =>
  JSON.parse(execFileSync("git", ["show", `${revision}:${file}`], { cwd, encoding: "utf8" }));

function readRelease() {
  const release = readJson(join(root, "release.json"));
  if (!FULL_COMMIT.test(release.source)) throw new Error("Expected a full source commit");
  if (!FULL_COMMIT.test(release.tufRelease)) throw new Error("Expected a full TUF release commit");
  if (release.node !== NODE || release.typescript !== TYPESCRIPT) {
    throw new Error("Unexpected release toolchain");
  }
  if (process.versions.node !== release.node) throw new Error(`Use Node ${release.node}`);
  return release;
}

// The source manifest and lockfile with lifecycle hooks removed and the TUF dependency moved from its
// pinned source commit to the prebuilt release commit. Returns them with that source pin.
function expectedPackage(release) {
  const manifest = releaseManifest(showJson(root, release.source, "package.json"));
  const lock = showJson(root, release.source, "package-lock.json");
  if (manifest.name !== "@freedomofpress/sigstore-browser") throw new Error("Unexpected package");
  if (manifest.devDependencies.typescript !== release.typescript) throw new Error("Compiler pin mismatch");

  const pinned = /^git\+(https:\/\/[^#]+\.git)#([a-f0-9]{40})$/.exec(manifest.dependencies[TUF_PACKAGE]);
  if (!pinned) throw new Error("Source must pin an exact TUF Git commit");
  const tufSource = { url: pinned[1], commit: pinned[2] };

  const spec = `git+${TUF_RELEASE_URL}#${release.tufRelease}`;
  manifest.dependencies[TUF_PACKAGE] = spec;
  lock.packages[""].dependencies[TUF_PACKAGE] = spec;
  const locked = lock.packages[`node_modules/${TUF_PACKAGE}`];
  locked.resolved = spec;
  // Git is pinned by its commit. npm ignores archive integrity for Git installs.
  delete locked.integrity;
  return { manifest, lock, tufSource };
}

function checkReleaseFiles(release, expected) {
  const manifest = readJson(join(root, "package.json"));
  for (const hook of preparationScripts) {
    if (Object.hasOwn(manifest.scripts ?? {}, hook)) throw new Error(`Forbidden release hook: ${hook}`);
  }
  if (Object.hasOwn(manifest, "workspaces")) throw new Error("Forbidden release workspaces");
  if (!isDeepStrictEqual(manifest, expected.manifest)) {
    throw new Error("package.json differs from the source release transformation");
  }
  if (!isDeepStrictEqual(readJson(join(root, "package-lock.json")), expected.lock)) {
    throw new Error("package-lock.json differs from the source release transformation");
  }
  // Entry-point code, build configuration and any additional tracked consumption files must match
  // the source too.
  run("git", ["diff", "--exit-code", release.source, "--", ".", ...GENERATED], root);
}

// Extracts `revision` of the repository at `repository` into `destination`.
function extract(repository, revision, destination, scratch) {
  mkdirSync(destination, { recursive: true });
  const archive = join(scratch, "archive.tar");
  run("git", ["archive", "--output", archive, revision], repository);
  run("tar", ["-xf", archive, "-C", destination], repository);
  rmSync(archive);
}

// The release pointer is not evidence of its contents: independently build the TUF source pinned by
// the browser source, and require the TUF release to be that build plus its own release metadata.
// Returns the TUF release manifest and the directory of the independently built dist/.
function checkTufRelease(release, tufSource, scratch) {
  const repository = join(scratch, "tuf-repository");
  mkdirSync(repository);
  run("git", ["init", "--quiet"], repository);
  run("git", ["fetch", "--quiet", "--no-tags", tufSource.url, tufSource.commit, release.tufRelease], repository);

  const provenance = showJson(repository, release.tufRelease, "release.json");
  if (provenance.source !== tufSource.commit) {
    throw new Error("TUF release source does not match the browser source dependency pin");
  }

  const sourceTree = join(scratch, "tuf-source");
  const releaseTree = join(scratch, "tuf-release");
  extract(repository, tufSource.commit, sourceTree, scratch);
  extract(repository, release.tufRelease, releaseTree, scratch);

  const manifest = releaseManifest(readJson(join(sourceTree, "package.json")));
  if (!isDeepStrictEqual(readJson(join(releaseTree, "package.json")), manifest)) {
    throw new Error("TUF release manifest differs from its pinned source transformation");
  }
  if (!isDeepStrictEqual(readJson(join(sourceTree, "package-lock.json")), readJson(join(releaseTree, "package-lock.json")))) {
    throw new Error("TUF release lockfile differs from its pinned source");
  }
  run("git", ["diff", "--exit-code", tufSource.commit, release.tufRelease, "--", ".", ...GENERATED], repository);

  run("npm", ["ci", "--ignore-scripts"], sourceTree);
  run("node", [join(sourceTree, "node_modules/typescript/bin/tsc"), "--project", "tsconfig.json"], sourceTree);
  run("diff", ["-r", join(sourceTree, "dist"), join(releaseTree, "dist")], root);
  return { manifest, dist: join(sourceTree, "dist") };
}

// Installs the release's dependencies as a consumer would, checks the installed TUF package against
// the independent build, then rebuilds this package and compares it with the committed dist/.
function checkBuild(release, tuf, scratch) {
  const build = join(scratch, "source");
  extract(root, release.source, build, scratch);
  for (const file of ["package.json", "package-lock.json"]) {
    copyFileSync(join(root, file), join(build, file));
  }
  run("npm", ["ci", "--ignore-scripts"], build);

  const installed = join(build, "node_modules", TUF_PACKAGE);
  if (!isDeepStrictEqual(readJson(join(installed, "package.json")), tuf.manifest)) {
    throw new Error("Installed TUF manifest differs from its pinned source transformation");
  }
  run("diff", ["-r", tuf.dist, join(installed, "dist")], root);

  run("node", [join(build, "node_modules/typescript/bin/tsc"), "--project", "tsconfig.json"], build);
  run("diff", ["-r", join(root, "dist"), join(build, "dist")], root);
}

const release = readRelease();
const expected = expectedPackage(release);
checkReleaseFiles(release, expected);
const scratch = mkdtempSync(join(tmpdir(), "release-check-"));
try {
  const tuf = checkTufRelease(release, expected.tufSource, scratch);
  checkBuild(release, tuf, scratch);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
