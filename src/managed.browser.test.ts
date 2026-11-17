import { describe, expect, inject, it } from "vitest";

import { base64ToBytes } from "../test/corpus/check.ts";
import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { REASON_CODES, VerificationError } from "./errors.js";
import { findDuplicateKey } from "./json.js";
import { ManagedKeyVerifier, type ManagedKeyVerifierOptions, STRICT_MANAGED_KEY_PROFILE } from "./managed.js";
import { SigstoreVerifier } from "./sigstore.js";

// Fixtures are the real Cosign bundles of the vendored corpus, mutated in place where a test needs it.
const corpus = inject("corpus");
const vector = (id: string): ManagedKeyVector => {
  const v = corpus.managedKey.find((x) => x.id === id);
  if (!v) throw new Error(`no vector ${id}`);
  return v;
};
const r1 = vector("p384-rekor2-dsse-tsa");
const r2 = vector("p384-rekor2-dsse-tsa-second-key");
const r3 = vector("p256-rekor2-dsse-tsa");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;
const bundleOf = (v: ManagedKeyVector): Json => JSON.parse(v.bundle);
const text = (b: unknown) => JSON.stringify(b, null, 2);

async function verifier(options: ManagedKeyVerifierOptions = STRICT_MANAGED_KEY_PROFILE, root: Json = JSON.parse(r1.root)) {
  const v = new ManagedKeyVerifier(options);
  await v.loadTrustedRoot(root);
  return v;
}

// The reason code a verification fails with, or "accept".
async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "accept";
  } catch (e) {
    if (e instanceof VerificationError) return e.code;
    throw e;
  }
}

// A certificate from a real keyless bundle in the conformance suite.
function realCertificate(): { rawBytes: string } {
  for (const v of corpus.conformance.filter((c) => !c.shouldFail)) {
    const cert = JSON.parse(v.bundle)?.verificationMaterial?.certificate;
    if (cert?.rawBytes) return cert;
  }
  throw new Error("no certificate in the conformance vectors");
}

describe("ManagedKeyVerifier", () => {
  it("verifies a P-384 DSSE bundle logged in Rekor v2 with a timestamp, using the caller's key", async () => {
    const v = await verifier();
    const result = await v.verifyDsse(r1.bundle, r1.key);
    expect(result.payloadType).toBe("application/vnd.in-toto+json");
    const statement = JSON.parse(new TextDecoder().decode(result.payload));
    expect(statement._type).toBe("https://in-toto.io/Statement/v1");
    expect(result.timestamps).toHaveLength(1);
    expect(result.timestamps[0].toISOString().slice(0, 10)).toBe("2026-11-17");
    // The same bytes, as UTF-8.
    await expect(v.verifyDsse(new TextEncoder().encode(r1.bundle), r1.key)).resolves.toBeDefined();
    // The key as DER works the same.
    const der = base64ToBytes(r1.key.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""));
    await expect(v.verifyDsse(r1.bundle, der)).resolves.toBeDefined();
    // P-256 too, and the artifact itself against the statement subject.
    await expect((await verifier()).verifyDsse(r3.bundle, r3.key)).resolves.toBeDefined();
    await expect(v.verifyArtifact(r1.bundle, r1.key, base64ToBytes(r1.artifact))).resolves.toBe(true);
    expect(await reason(v.verifyArtifact(r1.bundle, r1.key, new Uint8Array([1, 2, 3])))).toBe("artifact-mismatch");
  });

  it("uses only the caller's key: the bundle's key hint is never an authority", async () => {
    const v = await verifier();
    // Another real bundle, validly signed and logged under its own key, relabelled with r1's hint.
    const relabelled = bundleOf(r2);
    relabelled.verificationMaterial.publicKey.hint = bundleOf(r1).verificationMaterial.publicKey.hint;
    expect(await reason(v.verifyDsse(text(relabelled), r1.key))).toBe("dsse-signature-invalid");
    // The hint is not consulted at all: removing or replacing it changes nothing.
    for (const hint of [undefined, "", "not-a-key", bundleOf(r2).verificationMaterial.publicKey.hint]) {
      const b = bundleOf(r1);
      b.verificationMaterial.publicKey = hint === undefined ? {} : { hint };
      expect(await reason(v.verifyDsse(text(b), r1.key))).toBe("accept");
      expect(await reason(v.verifyDsse(text(b), r2.key))).toBe("dsse-signature-invalid");
    }
    // Without a usable caller key there is nothing to verify with.
    for (const key of ["", "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----", new Uint8Array(0)]) {
      expect(await reason(v.verifyDsse(r1.bundle, key))).toBe("key-unsupported");
    }
    // Ed25519 and P-521 keys are not managed-key signers here.
    const ed25519 = "MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=";
    expect(await reason(v.verifyDsse(r1.bundle, base64ToBytes(ed25519)))).toBe("key-unsupported");
    const p521 = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBi44fj79FBp5ZzPNa72pTsvb5XCoFTD6ThQen+AAGN8NEIRXjN5xTE+krQerNc/oLlVAZ/O5rVrI3qdmMzXqgtuAB6JSxfEck6S0RtgG85EgesH5/1aXaFnM9j5H/2j4eccHrB2c6whfZkS39TLg3nJEfV01Z+O3XUl0gmrr5RUpZfAQ=";
    expect(await reason(v.verifyDsse(r1.bundle, base64ToBytes(p521)))).toBe("key-unsupported");
  });

  it("rejects certificate material, alone or beside the public key", async () => {
    const certificate = realCertificate();
    for (const options of [STRICT_MANAGED_KEY_PROFILE, {}]) {
      const v = await verifier(options);
      const beside = bundleOf(r1);
      beside.verificationMaterial.certificate = certificate;
      expect(await reason(v.verifyDsse(text(beside), r1.key))).toBe("conflicting-oneof");
      const chain = bundleOf(r1);
      delete chain.verificationMaterial.publicKey;
      chain.verificationMaterial.x509CertificateChain = { certificates: [certificate] };
      expect(await reason(v.verifyDsse(text(chain), r1.key))).toBe("verification-material-unsupported");
      const alone = bundleOf(r1);
      delete alone.verificationMaterial.publicKey;
      alone.verificationMaterial.certificate = certificate;
      expect(await reason(v.verifyDsse(text(alone), r1.key))).toBe("verification-material-unsupported");
    }
  });

  it("rejects omitted and downgraded media types", async () => {
    const strict = await verifier();
    const relabel = (mediaType: unknown) => {
      const b = bundleOf(r1);
      if (mediaType === undefined) delete b.mediaType;
      else b.mediaType = mediaType;
      return text(b);
    };
    for (const mediaType of [
      undefined,
      null,
      "",
      "application/vnd.dev.sigstore.bundle+json;version=0.1",
      "application/vnd.dev.sigstore.bundle.v0.1+json",
      "application/vnd.dev.sigstore.bundle+json;version=0.2",
      "application/vnd.dev.sigstore.bundle.v0.2+json",
      "application/vnd.dev.sigstore.bundle.v0.4+json",
    ]) {
      expect(await reason(strict.verifyDsse(relabel(mediaType), r1.key))).toBe("media-type-unsupported");
    }
    // The strict profile requires the canonical spelling exactly; the legacy spelling of v0.3 is refused.
    const legacy = relabel("application/vnd.dev.sigstore.bundle+json;version=0.3");
    expect(await reason(strict.verifyDsse(legacy, r1.key))).toBe("media-type-unsupported");
    expect(await reason(strict.verifyDsse(relabel("application/vnd.dev.sigstore.bundle.v0.3+json"), r1.key))).toBe("accept");
    // By default, as for certificate bundles, both spellings of v0.2 and v0.3 are accepted and v0.1 is not.
    const lenient = await verifier({});
    expect(await reason(lenient.verifyDsse(legacy, r1.key))).toBe("accept");
    // The option alone, with the default versions.
    const canonical = await verifier({ requireCanonicalMediaType: true });
    expect(await reason(canonical.verifyDsse(legacy, r1.key))).toBe("media-type-unsupported");
    expect(await reason(canonical.verifyDsse(relabel("application/vnd.dev.sigstore.bundle+json;version=0.2"), r1.key))).toBe("media-type-unsupported");
    expect(await reason(canonical.verifyDsse(relabel("application/vnd.dev.sigstore.bundle.v0.2+json"), r1.key))).toBe("accept");
    expect(await reason(lenient.verifyDsse(relabel("application/vnd.dev.sigstore.bundle.v0.2+json"), r1.key))).toBe("accept");
    expect(await reason(lenient.verifyDsse(relabel("application/vnd.dev.sigstore.bundle.v0.1+json"), r1.key))).toBe("media-type-unsupported");
  });

  it("rejects duplicate JSON member names at any depth before parsing", async () => {
    const v = await verifier();
    const top = r1.bundle.replace('"mediaType":', '"mediaType": "x", "mediaType":');
    const escaped = r1.bundle.replace('"mediaType":', '"\\u006dediaType": "x", "mediaType":');
    const nested = r1.bundle.replace('"logIndex":', '"logIndex": "1", "logIndex":');
    for (const b of [top, escaped, nested]) {
      expect(b).not.toBe(r1.bundle);
      expect(await reason(v.verifyDsse(b, r1.key))).toBe("duplicate-json-key");
    }
    expect(findDuplicateKey(nested)).toMatch(/tlogEntries\[0\]\.logIndex$/);
    expect(findDuplicateKey('{"a":[{"b":1},{"b":2}],"c":{"b":3}}')).toBeUndefined();
    expect(await reason(v.verifyDsse(r1.bundle.slice(0, -10), r1.key))).toBe("bundle-malformed");
    expect(await reason(v.verifyDsse("[".repeat(100) + "]".repeat(100), r1.key))).toBe("bundle-malformed");
    // The check needs the text, so an already parsed object is refused rather than silently unchecked.
    await expect(v.verifyDsse(bundleOf(r1), r1.key)).rejects.toThrow(TypeError);
    // Without the option a parsed object is accepted, as for certificate bundles.
    await expect((await verifier({})).verifyDsse(bundleOf(r1), r1.key)).resolves.toBeDefined();
  });

  it("bounds the input size before parsing", async () => {
    const v = await verifier({ ...STRICT_MANAGED_KEY_PROFILE, maxBundleBytes: r1.bundle.length - 1 });
    expect(await reason(v.verifyDsse(r1.bundle, r1.key))).toBe("bundle-too-large");
    expect(await reason(v.verifyDsse(new TextEncoder().encode(r1.bundle), r1.key))).toBe("bundle-too-large");
    const exact = await verifier({ ...STRICT_MANAGED_KEY_PROFILE, maxBundleBytes: r1.bundle.length });
    expect(await reason(exact.verifyDsse(r1.bundle, r1.key))).toBe("accept");
    // Multi-byte characters count as their UTF-8 length.
    const padded = r1.bundle.replace('"mediaType"', `"x": "${"é".repeat(400)}", "mediaType"`);
    const tight = await verifier({ ...STRICT_MANAGED_KEY_PROFILE, maxBundleBytes: padded.length + 100 });
    expect(await reason(tight.verifyDsse(padded, r1.key))).toBe("bundle-too-large");
    expect(await reason(v.verifyDsse(new Uint8Array([0x7b, 0xff, 0x7d]), r1.key))).toBe("bundle-malformed");
  });

  it("rejects extra log entries, Rekor v1 metadata and extra timestamps only in the strict profile", async () => {
    const strict = await verifier();
    const lenient = await verifier({});
    const twoEntries = bundleOf(r1);
    twoEntries.verificationMaterial.tlogEntries.push(structuredClone(twoEntries.verificationMaterial.tlogEntries[0]));
    expect(await reason(strict.verifyDsse(text(twoEntries), r1.key))).toBe("tlog-entry-count");
    expect(await reason(lenient.verifyDsse(text(twoEntries), r1.key))).toBe("accept");
    const none = bundleOf(r1);
    none.verificationMaterial.tlogEntries = [];
    expect(await reason(strict.verifyDsse(text(none), r1.key))).toBe("tlog-entry-count");
    expect(await reason(lenient.verifyDsse(text(none), r1.key))).toBe("bundle-malformed");
    // An entry naming a log outside the trusted root is ignored by default (then too few logs verify)
    // and rejected when checkpoints are bound to the entry's log.
    const unknown = bundleOf(r1);
    unknown.verificationMaterial.tlogEntries[0].logId.keyId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    expect(await reason(strict.verifyDsse(text(unknown), r1.key))).toBe("tlog-unknown-log");
    expect(await reason(lenient.verifyDsse(text(unknown), r1.key))).toBe("tlog-threshold");
  });

  it("does not let an unsupported, malformed or retired trusted-root key stop unrelated verification", async () => {
    const root = JSON.parse(r1.root);
    root.tlogs.push(
      // An unknown key type and a key that is not valid base64 DER.
      { ...structuredClone(root.tlogs[0]), logId: { keyId: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" }, publicKey: { rawBytes: "AAAA", keyDetails: "PKIX_SOMETHING_NEW", validFor: { start: "2026-01-01T00:00:00Z" } } },
      { ...structuredClone(root.tlogs[0]), logId: { keyId: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" }, publicKey: { rawBytes: "!!!", keyDetails: "PKIX_ECDSA_P256_SHA_256", validFor: { start: "2026-01-01T00:00:00Z" } } },
      // A malformed validity period.
      { ...structuredClone(root.tlogs[0]), logId: { keyId: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" }, publicKey: { ...structuredClone(root.tlogs[0].publicKey), validFor: { start: "not a date" } } },
      // Retired logs (validity ended) from the real staging root.
      ...JSON.parse(corpus.stagingRoot).tlogs.filter((l: Json) => l.publicKey.validFor.end),
      "not an object",
    );
    // The staging root's retired RSA CT log key, and a CT key that does not parse.
    root.ctlogs.push(
      ...JSON.parse(corpus.stagingRoot).ctlogs.filter((l: Json) => l.publicKey.keyDetails === "PKCS1_RSA_PKCS1V5"),
      { ...structuredClone(root.ctlogs[0]), publicKey: { rawBytes: "AAAA", keyDetails: "PKIX_ECDSA_P256_SHA_256", validFor: { start: "2021-01-01T00:00:00Z" } } },
    );
    root.timestampAuthorities.push(
      { ...structuredClone(root.timestampAuthorities[0]), validFor: { start: "not a date" } },
      { ...structuredClone(root.timestampAuthorities[0]), certChain: { certificates: [{ rawBytes: "AAAA" }] } },
    );
    expect(await reason((await verifier(STRICT_MANAGED_KEY_PROFILE, root)).verifyDsse(r1.bundle, r1.key))).toBe("accept");
    // The certificate flow's loader fails on the same root as a whole.
    await expect(new SigstoreVerifier().loadSigstoreRoot(root)).rejects.toThrow();

    // An entry that does need an unusable key fails, without accepting.
    const broken = JSON.parse(r1.root);
    const log2025 = broken.tlogs.find((l: Json) => l.baseUrl.includes("log2025-1"));
    log2025.publicKey.rawBytes = "AAAA";
    expect(await reason((await verifier(STRICT_MANAGED_KEY_PROFILE, broken)).verifyDsse(r1.bundle, r1.key))).toBe("tlog-log-key-unsupported");
  });

  it("validates its options", () => {
    for (const key of ["tlogThreshold", "tsaThreshold", "maxBundleBytes"] as const) {
      for (const value of [-1, 0.5, NaN, Infinity]) {
        expect(() => new ManagedKeyVerifier({ [key]: value })).toThrow("non-negative safe integer");
      }
    }
    expect(() => new ManagedKeyVerifier({ bundleVersions: [] })).toThrow("bundleVersions");
    expect(() => new ManagedKeyVerifier({ bundleVersions: ["0.4"] })).toThrow("bundleVersions");
    expect(Object.isFrozen(STRICT_MANAGED_KEY_PROFILE)).toBe(true);
    expect(new Set(REASON_CODES).size).toBe(REASON_CODES.length);
  });

  it("needs a trusted root", async () => {
    await expect(new ManagedKeyVerifier().verifyDsse(r1.bundle, r1.key)).rejects.toThrow("Trusted root is not loaded");
  });
});
