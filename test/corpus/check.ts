// Runs the vendored vectors against the library and reports every outcome that differs from the
// expected one. Runtime-agnostic (Node, Bun, browsers): it receives the library and the data.
import { verifySignatureOverDigest } from "@freedomofpress/crypto-browser/noble";

import type * as library from "../../src/index.ts";
import type { ConformanceVector, Corpus, Expected, ManagedKeyVector } from "./data.ts";

/** The parts of the library the checks use: the source in tests, the built dist/ in runtime-matrix.ts. */
export type Lib = Pick<typeof library, "ManagedKeyVerifier" | "STRICT_MANAGED_KEY_PROFILE" | "SigstoreVerifier">;

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

// The digest a messageSignature signed: the hash the key implies (SHA-256 for P-256, SHA-384 for
// P-384). DSSE bundles keep SHA-256, matching their in-toto subject digests.
const P256_ALGID = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_ALGID = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const hasCurve = (der: Uint8Array, algid: number[]) => {
  outer: for (let i = 0; i + algid.length <= der.length; i++) {
    for (let j = 0; j < algid.length; j++) if (der[i + j] !== algid[j]) continue outer;
    return true;
  }
  return false;
};
const digestForVector = async (v: ManagedKeyVector, artifact: Uint8Array): Promise<Uint8Array> => {
  if (!JSON.parse(v.bundle).messageSignature) return sha256(artifact);
  const der = base64ToBytes(v.key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  // Read the curve from the SPKI algorithm identifier: trial imports are not
  // portable (some engines accept a P-256 key where P-384 is requested).
  const name = hasCurve(der, P384_ALGID) ? "SHA-384" : hasCurve(der, P256_ALGID) ? "SHA-256" : (() => { throw new Error("unrecognized EC curve in SPKI"); })();
  return new Uint8Array(await crypto.subtle.digest(name, artifact));
};

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

// A messageSignature bundle has no DSSE envelope, so verifyDsse must refuse it.
const hasDsseEnvelope = (v: ManagedKeyVector): boolean => Boolean(JSON.parse(v.bundle).dsseEnvelope);

// In "dsse" mode, messageSignature vectors are expected to be refused with content-unsupported;
// the manifest records outcomes for the verifying paths only.
const expectedForHow = (v: ManagedKeyVector, mode: Mode, how: How): Expected =>
  how === "dsse" && !hasDsseEnvelope(v) ? { result: "reject", code: "content-unsupported" } : expectedFor(v, mode);

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
  const options = { ...(mode === "strict" ? lib.STRICT_MANAGED_KEY_PROFILE : {}), verifyDigest: verifySignatureOverDigest };
  const verifier = new lib.ManagedKeyVerifier(options);
  await verifier.loadTrustedRoot(JSON.parse(v.root));
  return outcome(async () => {
    if (how === "dsse") {
      await verifier.verifyDsse(v.bundle, v.key);
    } else {
      const artifact = base64ToBytes(v.artifact);
      const data = how === "digest" ? await digestForVector(v, artifact) : artifact;
      await verifier.verifyArtifact(v.bundle, v.key, data, how === "digest");
    }
  });
}

const matches = (expected: Expected, actual: Outcome) =>
  expected.result === actual.result && (expected.result === "accept" || expected.code === actual.code);

/** Every managed-key vector, plus a check that each negative's parent is accepted in the same mode. */
export async function checkManagedKeyCorpus(lib: Lib, vectors: ManagedKeyVector[], mode: Mode, how: How): Promise<Mismatch[]> {
  const mismatches: Mismatch[] = [];
  const outcomes = new Map<string, Outcome>();
  const byId = new Map(vectors.map((v) => [v.id, v]));
  for (const v of vectors) {
    const actual = await verifyManagedKeyVector(lib, v, mode, how);
    outcomes.set(v.id, actual);
    const expected = expectedForHow(v, mode, how);
    if (!matches(expected, actual)) mismatches.push({ id: v.id, how: `${mode}/${how}`, expected, actual });
  }
  for (const v of vectors) {
    if (!v.parent) continue;
    // A messageSignature parent cannot be accepted by verifyDsse; skip the parent check there.
    const parent = byId.get(v.parent);
    if (how === "dsse" && parent && !hasDsseEnvelope(parent)) continue;
    if (outcomes.get(v.parent)?.result !== "accept") {
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
