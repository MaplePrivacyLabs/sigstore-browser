// Reads the vendored vectors from disk into plain, serializable data, so that the same checks can
// run in Node, Bun and (through vitest's provide/inject) in browsers. Node-only.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const VECTORS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../vectors");

export type Expected =
  | { result: "accept" }
  | { result: "reject"; code: string; error?: string; message?: string; clause?: string; reason?: string };

export interface ManagedKeyVector {
  id: string;
  category: string;
  parent: string | null;
  bundle: string; // JSON text, exactly as stored
  key: string; // PEM
  artifact: string; // base64
  root: string; // JSON text
  expected: { library: Expected; library_checkpoint_log_binding: Expected; profile: Expected };
}

export interface ConformanceVector {
  id: string;
  shouldFail: boolean;
  bundle: string;
  key?: string;
  artifact: string; // base64
  root: string;
  identity: string;
  issuer: string;
}

export interface Corpus {
  managedKey: ManagedKeyVector[];
  conformance: ConformanceVector[];
  // Sigstore's staging trusted root (TUF snapshot), which has retired logs and an RSA CT log key.
  stagingRoot: string;
}

const read = (file: string) => readFileSync(file, "utf8");
const readB64 = (file: string) => readFileSync(file).toString("base64");

// The fields of a manifest.json vector that the checks use; file fields are paths relative to it.
interface ManifestVector {
  id: string;
  category: string;
  parent: string | null;
  bundle: string;
  key: string;
  artifact: string;
  trusted_root: string;
  expected: ManagedKeyVector["expected"];
}

export function loadManagedKeyCorpus(dir = path.join(VECTORS_DIR, "managed-key")): ManagedKeyVector[] {
  const manifest: { vectors: ManifestVector[] } = JSON.parse(read(path.join(dir, "manifest.json")));
  return manifest.vectors.map((v) => ({
    id: v.id,
    category: v.category,
    parent: v.parent,
    bundle: read(path.join(dir, v.bundle)),
    key: read(path.join(dir, v.key)),
    artifact: readB64(path.join(dir, v.artifact)),
    root: read(path.join(dir, v.trusted_root)),
    expected: v.expected,
  }));
}

const DEFAULT_IDENTITY =
  "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
const DEFAULT_ISSUER = "https://token.actions.githubusercontent.com";

// Follows bundle-verify/README.md of sigstore-conformance. Vectors without their own trusted root use
// the Sigstore production root snapshot vendored with the managed-key corpus.
export function loadConformance(
  dir = path.join(VECTORS_DIR, "sigstore-conformance", "bundle-verify"),
  productionRoot = path.join(VECTORS_DIR, "managed-key", "sources", "trusted_root.production.json"),
): ConformanceVector[] {
  const optional = (file: string) => (existsSync(file) ? read(file).trim() : undefined);
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort()
    .map((id) => {
      const vdir = path.join(dir, id);
      const vectorArtifact = path.join(vdir, "artifact");
      const artifact = existsSync(vectorArtifact) ? vectorArtifact : path.join(dir, "a.txt");
      const vectorRoot = path.join(vdir, "trusted_root.json");
      const trustedRoot = existsSync(vectorRoot) ? vectorRoot : productionRoot;
      return {
        id,
        shouldFail: id.endsWith("_fail"),
        bundle: read(path.join(vdir, "bundle.sigstore.json")),
        key: existsSync(path.join(vdir, "key.pub")) ? read(path.join(vdir, "key.pub")) : undefined,
        artifact: readB64(artifact),
        root: read(trustedRoot),
        identity: optional(path.join(vdir, "identity")) ?? DEFAULT_IDENTITY,
        issuer: optional(path.join(vdir, "issuer")) ?? DEFAULT_ISSUER,
      };
    });
}

export function loadCorpus(): Corpus {
  return {
    managedKey: loadManagedKeyCorpus(),
    conformance: loadConformance(),
    stagingRoot: read(path.join(VECTORS_DIR, "managed-key", "sources", "trusted_root.staging.json")),
  };
}
