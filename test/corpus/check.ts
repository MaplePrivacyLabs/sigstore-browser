// Runs the vendored vectors against the library and reports every outcome that differs from the
// expected one. Runtime-agnostic (Node, Bun, browsers): it receives the library and the data.
import type { ConformanceVector, Corpus, Expected, ManagedKeyVector } from "./data.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface Lib {
  ManagedKeyVerifier: any;
  STRICT_MANAGED_KEY_PROFILE: any;
  SigstoreVerifier: any;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export interface Outcome {
  result: "accept" | "reject";
  code?: string;
  message?: string;
}

export interface Mismatch {
  id: string;
  how: string;
  expected: Expected;
  actual: Outcome;
}

export type Mode = "strict" | "default";
export type How = "dsse" | "artifact" | "digest";

export const base64ToBytes = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const sha256 = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

/**
 * Where the default (upstream-consistent) configuration intentionally differs from sigstore-rust's
 * library defaults ("library" in the manifest). In strict mode there are no differences: every vector
 * must match the manifest's "profile" outcome and reason code.
 */
export const DEFAULT_MODE_DIFFERENCES: Record<string, { expected: Expected; why: string }> = {
  "p384-entry-names-another-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p256-entry-names-another-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p384-checkpoint-signed-by-other-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p384-timestamp-removed": {
    expected: { result: "reject", code: "timestamp-count" },
    why: "a verified observer time is required, as in the certificate flow; Rekor v2 entries carry none",
  },
  "p384-timestamp-duplicated": {
    expected: { result: "reject", code: "timestamp-duplicate" },
    why: "duplicate timestamps are rejected, as in the certificate flow",
  },
  "p384-extra-entry-without-proof": {
    expected: { result: "reject", code: "inclusion-proof-missing" },
    why: "every entry from a trusted log is verified, and v0.2+ entries need an inclusion proof",
  },
  "p384-rekor2-integrated-time-zero-number": {
    expected: { result: "reject", code: "bundle-malformed" },
    why: "int64 fields must be JSON strings, as in the certificate flow",
  },
  "p384-rekor2-integrated-time-null": {
    expected: { result: "accept" },
    why: "a null integratedTime is read as absent, as in the certificate flow",
  },
  "p384-rekor2-inclusion-promise-added": {
    expected: { result: "reject", code: "bundle-malformed" },
    why: "an inclusion promise without an integratedTime is malformed, as in the certificate flow",
  },
  "p384-media-type-missing": {
    expected: { result: "reject", code: "media-type-unsupported" },
    why: "a missing media type is rejected rather than read as v0.1, as in the certificate flow",
  },
  "p384-duplicate-dsse-envelope-key": {
    expected: { result: "reject", code: "dsse-signature-invalid" },
    why: "JSON.parse keeps the last dsseEnvelope (another key's); sigstore-rust keeps the first",
  },
  "p384-conflicting-content": {
    expected: { result: "reject", code: "conflicting-oneof" },
    why: "conflicting oneof variants are always rejected",
  },
};

export function expectedFor(v: ManagedKeyVector, mode: Mode): Expected {
  if (mode === "strict") return v.expected.profile;
  return DEFAULT_MODE_DIFFERENCES[v.id]?.expected ?? v.expected.library;
}

async function outcome(fn: () => Promise<unknown>): Promise<Outcome> {
  try {
    await fn();
    return { result: "accept" };
  } catch (e) {
    const err = e as { code?: unknown; message?: unknown };
    return { result: "reject", code: typeof err.code === "string" ? err.code : undefined, message: String(err.message ?? e) };
  }
}

export async function verifyManagedKeyVector(lib: Lib, v: ManagedKeyVector, mode: Mode, how: How): Promise<Outcome> {
  const options = mode === "strict" ? { ...lib.STRICT_MANAGED_KEY_PROFILE } : {};
  const verifier = new lib.ManagedKeyVerifier(options);
  await verifier.loadTrustedRoot(JSON.parse(v.root));
  return outcome(async () => {
    if (how === "dsse") {
      await verifier.verifyDsse(v.bundle, v.key);
    } else {
      const artifact = base64ToBytes(v.artifact);
      await verifier.verifyArtifact(v.bundle, v.key, how === "digest" ? await sha256(artifact) : artifact, how === "digest");
    }
  });
}

const matches = (expected: Expected, actual: Outcome) =>
  expected.result === actual.result && (expected.result === "accept" || expected.code === actual.code);

/** Every managed-key vector, plus a check that each negative's parent is accepted in the same mode. */
export async function checkManagedKeyCorpus(lib: Lib, vectors: ManagedKeyVector[], mode: Mode, how: How): Promise<Mismatch[]> {
  const mismatches: Mismatch[] = [];
  const outcomes = new Map<string, Outcome>();
  for (const v of vectors) {
    const actual = await verifyManagedKeyVector(lib, v, mode, how);
    outcomes.set(v.id, actual);
    const expected = expectedFor(v, mode);
    if (!matches(expected, actual)) mismatches.push({ id: v.id, how: `${mode}/${how}`, expected, actual });
  }
  for (const v of vectors) {
    if (v.parent && outcomes.get(v.parent)?.result !== "accept") {
      mismatches.push({ id: `${v.id} (parent ${v.parent})`, how: `${mode}/${how}`, expected: { result: "accept" }, actual: outcomes.get(v.parent) ?? { result: "reject" } });
    }
  }
  return mismatches;
}

/**
 * sigstore-conformance bundle-verify vectors at the library level, from the artifact and from its
 * SHA-256 digest, as the suite's harness does. key.pub selects ManagedKeyVerifier, otherwise the
 * certificate flow (SigstoreVerifier) with the vector's identity and issuer. Like the suite's CLI
 * entry point, every bundle version is enabled.
 */
export async function checkConformance(
  lib: Lib,
  vectors: ConformanceVector[],
  verifyDigest: (key: CryptoKey, digest: Uint8Array, signature: Uint8Array) => Promise<boolean>,
): Promise<Mismatch[]> {
  const mismatches: Mismatch[] = [];
  const bundleVersions = ["0.1", "0.2", "0.3"];
  for (const v of vectors) {
    for (const digestOnly of [false, true]) {
      const artifact = base64ToBytes(v.artifact);
      const data = digestOnly ? await sha256(artifact) : artifact;
      const actual = await outcome(async () => {
        if (v.key !== undefined) {
          const verifier = new lib.ManagedKeyVerifier({ bundleVersions, verifyDigest });
          await verifier.loadTrustedRoot(JSON.parse(v.root));
          await verifier.verifyArtifact(v.bundle, v.key, data, digestOnly);
        } else {
          const verifier = new lib.SigstoreVerifier({ bundleVersions, verifyDigest });
          await verifier.loadSigstoreRoot(JSON.parse(v.root));
          await verifier.verifyArtifact(v.identity, v.issuer, JSON.parse(v.bundle), data, digestOnly);
        }
      });
      const expected: Expected = v.shouldFail ? { result: "reject", code: "" } : { result: "accept" };
      if (expected.result !== actual.result) {
        mismatches.push({ id: v.id, how: digestOnly ? "digest" : "artifact", expected, actual });
      }
    }
  }
  return mismatches;
}

export type { Corpus };
