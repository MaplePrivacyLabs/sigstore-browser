import { describe, expect, inject, it } from "vitest";

import { base64ToBytes } from "../test/corpus/check.ts";
import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { bundle as keylessBundle } from "../test/fixtures/sigstore.js";
import { VerificationError } from "./errors.js";
import { findDuplicateKey } from "./json.js";
import { ManagedKeyVerifier, type ManagedKeyVerifierOptions, STRICT_MANAGED_KEY_PROFILE } from "./managed.js";
import { SigstoreVerifier } from "./sigstore.js";

// Fixtures are real Cosign bundles from the vendored corpus. Tests parse them, change one thing and
// serialize them again, so parsed bundles and roots are plain mutable JSON.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

const corpus = inject("corpus");
const vector = (id: string): ManagedKeyVector => {
  const v = corpus.managedKey.find((x) => x.id === id);
  if (!v) throw new Error(`no vector ${id}`);
  return v;
};

const p384 = vector("p384-rekor2-dsse-tsa");
const otherP384 = vector("p384-rekor2-dsse-tsa-second-key");
const p256 = vector("p256-rekor2-dsse-tsa");
// The day the corpus bundles were signed and timestamped.
const SIGNING_DAY = "2026-11-17";

const LEGACY_V01 = "application/vnd.dev.sigstore.bundle+json;version=0.1";
const LEGACY_V02 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
const LEGACY_V03 = "application/vnd.dev.sigstore.bundle+json;version=0.3";
const CANONICAL_V01 = "application/vnd.dev.sigstore.bundle.v0.1+json";
const CANONICAL_V02 = "application/vnd.dev.sigstore.bundle.v0.2+json";
const CANONICAL_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
const CANONICAL_V04 = "application/vnd.dev.sigstore.bundle.v0.4+json";

const STRICT = STRICT_MANAGED_KEY_PROFILE;
const DEFAULTS: ManagedKeyVerifierOptions = {};
const CANONICAL_ONLY: ManagedKeyVerifierOptions = { requireCanonicalMediaType: true };

const parse = (v: ManagedKeyVector): Json => JSON.parse(v.bundle);
const text = (bundle: unknown) => JSON.stringify(bundle, null, 2);

/** p384's bundle as text, after `change` has modified its parsed form. */
function changed(change: (bundle: Json) => void): string {
  const bundle = parse(p384);
  change(bundle);
  return text(bundle);
}

const withMediaType = (mediaType: unknown) =>
  changed((b) => {
    if (mediaType === undefined) delete b.mediaType;
    else b.mediaType = mediaType;
  });

async function verifier(options: ManagedKeyVerifierOptions = STRICT, root: Json = JSON.parse(p384.root)) {
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

/**
 * p384's trusted root with logs, CT logs and timestamp authorities this library cannot load or does
 * not need: an unknown key type, a key that is not base64 DER, a malformed validity period, the
 * staging root's retired logs and RSA CT key, a CT key that does not parse, and broken authorities.
 */
function rootWithUnusableKeys(): Json {
  const root = JSON.parse(p384.root);
  const stagingRoot = JSON.parse(corpus.stagingRoot);
  const [log] = root.tlogs;
  const [ctLog] = root.ctlogs;
  const [authority] = root.timestampAuthorities;

  root.tlogs.push(
    {
      ...structuredClone(log),
      logId: { keyId: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" },
      publicKey: { rawBytes: "AAAA", keyDetails: "PKIX_SOMETHING_NEW", validFor: { start: "2026-01-01T00:00:00Z" } },
    },
    {
      ...structuredClone(log),
      logId: { keyId: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" },
      publicKey: { rawBytes: "!!!", keyDetails: "PKIX_ECDSA_P256_SHA_256", validFor: { start: "2026-01-01T00:00:00Z" } },
    },
    {
      ...structuredClone(log),
      logId: { keyId: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" },
      publicKey: { ...structuredClone(log.publicKey), validFor: { start: "not a date" } },
    },
    ...stagingRoot.tlogs.filter((l: Json) => l.publicKey.validFor.end),
    "not an object",
  );
  root.ctlogs.push(
    ...stagingRoot.ctlogs.filter((l: Json) => l.publicKey.keyDetails === "PKCS1_RSA_PKCS1V5"),
    {
      ...structuredClone(ctLog),
      publicKey: { rawBytes: "AAAA", keyDetails: "PKIX_ECDSA_P256_SHA_256", validFor: { start: "2021-01-01T00:00:00Z" } },
    },
  );
  root.timestampAuthorities.push(
    { ...structuredClone(authority), validFor: { start: "not a date" } },
    { ...structuredClone(authority), certChain: { certificates: [{ rawBytes: "AAAA" }] } },
  );
  return root;
}

describe("ManagedKeyVerifier", () => {
  describe("verification", () => {
    it("verifies a P-384 DSSE bundle logged in Rekor v2 with a timestamp, using the caller's key", async () => {
      const result = await (await verifier()).verifyDsse(p384.bundle, p384.key);

      expect(result.payloadType).toBe("application/vnd.in-toto+json");
      const statement = JSON.parse(new TextDecoder().decode(result.payload));
      expect(statement._type).toBe("https://in-toto.io/Statement/v1");
      expect(result.timestamps).toHaveLength(1);
      expect(result.timestamps[0].toISOString().slice(0, 10)).toBe(SIGNING_DAY);
    });

    it("accepts the bundle as UTF-8 bytes", async () => {
      const bytes = new TextEncoder().encode(p384.bundle);
      await expect((await verifier()).verifyDsse(bytes, p384.key)).resolves.toBeDefined();
    });

    it("accepts the key as DER SubjectPublicKeyInfo", async () => {
      const der = base64ToBytes(p384.key.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""));
      await expect((await verifier()).verifyDsse(p384.bundle, der)).resolves.toBeDefined();
    });

    it("verifies a P-256 bundle", async () => {
      await expect((await verifier()).verifyDsse(p256.bundle, p256.key)).resolves.toBeDefined();
    });

    it("accepts the artifact named by the statement subject", async () => {
      const artifact = base64ToBytes(p384.artifact);
      await expect((await verifier()).verifyArtifact(p384.bundle, p384.key, artifact)).resolves.toBe(true);
    });

    it("rejects an artifact that is not the statement subject", async () => {
      const other = new Uint8Array([1, 2, 3]);
      expect(await reason((await verifier()).verifyArtifact(p384.bundle, p384.key, other))).toBe("artifact-mismatch");
    });
  });

  describe("key authority", () => {
    it("rejects another key's bundle relabelled with this key's hint", async () => {
      const relabelled = parse(otherP384);
      relabelled.verificationMaterial.publicKey.hint = parse(p384).verificationMaterial.publicKey.hint;

      expect(await reason((await verifier()).verifyDsse(text(relabelled), p384.key))).toBe("dsse-signature-invalid");
    });

    it.each([
      { name: "removed", hint: undefined },
      { name: "empty", hint: "" },
      { name: "garbage", hint: "not-a-key" },
      { name: "another key's", hint: parse(otherP384).verificationMaterial.publicKey.hint },
    ])("ignores the key hint when it is $name", async ({ hint }) => {
      const bundle = changed((b) => {
        b.verificationMaterial.publicKey = hint === undefined ? {} : { hint };
      });
      const v = await verifier();

      expect(await reason(v.verifyDsse(bundle, p384.key))).toBe("accept");
      expect(await reason(v.verifyDsse(bundle, otherP384.key))).toBe("dsse-signature-invalid");
    });

    it.each([
      { name: "an empty string", key: "" },
      { name: "a certificate", key: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" },
      { name: "empty bytes", key: new Uint8Array(0) },
      { name: "an Ed25519 key", key: base64ToBytes("MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=") },
      {
        name: "a P-521 key",
        key: base64ToBytes(
          "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBi44fj79FBp5ZzPNa72pTsvb5XCoFTD6ThQen+AAGN8NEIRXjN5xTE+krQerNc/oLlVAZ/O5rVrI3qdmMzXqgtuAB6JSxfEck6S0RtgG85EgesH5/1aXaFnM9j5H/2j4eccHrB2c6whfZkS39TLg3nJEfV01Z+O3XUl0gmrr5RUpZfAQ=",
        ),
      },
    ])("rejects $name as the caller's key", async ({ key }) => {
      expect(await reason((await verifier()).verifyDsse(p384.bundle, key))).toBe("key-unsupported");
    });
  });

  describe("certificate material", () => {
    const certificate = keylessBundle().verificationMaterial.certificate;

    it("has a certificate fixture", () => {
      expect(certificate?.rawBytes).toBeTruthy();
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate beside the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        b.verificationMaterial.certificate = certificate;
      });
      expect(await reason((await verifier(options)).verifyDsse(bundle, p384.key))).toBe("conflicting-oneof");
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate chain instead of the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        delete b.verificationMaterial.publicKey;
        b.verificationMaterial.x509CertificateChain = { certificates: [certificate] };
      });
      expect(await reason((await verifier(options)).verifyDsse(bundle, p384.key))).toBe(
        "verification-material-unsupported",
      );
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate instead of the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        delete b.verificationMaterial.publicKey;
        b.verificationMaterial.certificate = certificate;
      });
      expect(await reason((await verifier(options)).verifyDsse(bundle, p384.key))).toBe(
        "verification-material-unsupported",
      );
    });
  });

  describe("media types", () => {
    it.each([
      { name: "a missing media type", mediaType: undefined },
      { name: "null", mediaType: null },
      { name: "an empty media type", mediaType: "" },
      { name: "legacy v0.1", mediaType: LEGACY_V01 },
      { name: "v0.1", mediaType: CANONICAL_V01 },
      { name: "legacy v0.2", mediaType: LEGACY_V02 },
      { name: "v0.2", mediaType: CANONICAL_V02 },
      { name: "v0.4", mediaType: CANONICAL_V04 },
      { name: "legacy v0.3", mediaType: LEGACY_V03 },
    ])("strict profile rejects $name", async ({ mediaType }) => {
      expect(await reason((await verifier()).verifyDsse(withMediaType(mediaType), p384.key))).toBe(
        "media-type-unsupported",
      );
    });

    it("strict profile accepts the canonical v0.3 media type", async () => {
      expect(await reason((await verifier()).verifyDsse(withMediaType(CANONICAL_V03), p384.key))).toBe("accept");
    });

    // As for certificate bundles: both spellings of v0.2 and v0.3, and not v0.1.
    it.each([
      { name: "legacy v0.3", mediaType: LEGACY_V03, expected: "accept" },
      { name: "v0.2", mediaType: CANONICAL_V02, expected: "accept" },
      { name: "v0.1", mediaType: CANONICAL_V01, expected: "media-type-unsupported" },
    ])("default configuration gives $expected for $name", async ({ mediaType, expected }) => {
      expect(await reason((await verifier(DEFAULTS)).verifyDsse(withMediaType(mediaType), p384.key))).toBe(expected);
    });

    it.each([
      { name: "legacy v0.3", mediaType: LEGACY_V03, expected: "media-type-unsupported" },
      { name: "legacy v0.2", mediaType: LEGACY_V02, expected: "media-type-unsupported" },
      { name: "v0.2", mediaType: CANONICAL_V02, expected: "accept" },
    ])("requireCanonicalMediaType alone gives $expected for $name", async ({ mediaType, expected }) => {
      expect(await reason((await verifier(CANONICAL_ONLY)).verifyDsse(withMediaType(mediaType), p384.key))).toBe(
        expected,
      );
    });
  });

  describe("repeated JSON member names", () => {
    const duplicated = {
      topLevel: p384.bundle.replace('"mediaType":', '"mediaType": "x", "mediaType":'),
      escaped: p384.bundle.replace('"mediaType":', '"\\u006dediaType": "x", "mediaType":'),
      nested: p384.bundle.replace('"logIndex":', '"logIndex": "1", "logIndex":'),
    };

    it.each(Object.entries(duplicated).map(([name, bundle]) => ({ name, bundle })))(
      "rejects a $name repeated member name",
      async ({ bundle }) => {
        expect(bundle).not.toBe(p384.bundle);
        expect(await reason((await verifier()).verifyDsse(bundle, p384.key))).toBe("duplicate-json-key");
      },
    );

    it("reports the path of the repeated member", () => {
      expect(findDuplicateKey(duplicated.nested)).toMatch(/tlogEntries\[0\]\.logIndex$/);
    });

    it("does not count the same name in different objects", () => {
      expect(findDuplicateKey('{"a":[{"b":1},{"b":2}],"c":{"b":3}}')).toBeUndefined();
    });

    it("rejects truncated JSON as bundle-malformed", async () => {
      expect(await reason((await verifier()).verifyDsse(p384.bundle.slice(0, -10), p384.key))).toBe("bundle-malformed");
    });

    it("rejects JSON nested deeper than the scanner allows as bundle-malformed", async () => {
      const deep = "[".repeat(100) + "]".repeat(100);
      expect(await reason((await verifier()).verifyDsse(deep, p384.key))).toBe("bundle-malformed");
    });

    // The check needs the text, so an already parsed object is refused rather than silently unchecked.
    it("refuses an already parsed bundle when repeated names must be rejected", async () => {
      await expect((await verifier()).verifyDsse(parse(p384), p384.key)).rejects.toThrow(TypeError);
    });

    it("accepts an already parsed bundle by default, as for certificate bundles", async () => {
      await expect((await verifier(DEFAULTS)).verifyDsse(parse(p384), p384.key)).resolves.toBeDefined();
    });
  });

  describe("input size", () => {
    const withLimit = (maxBundleBytes: number) => verifier({ ...STRICT, maxBundleBytes });

    it("rejects text one byte over the limit", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      expect(await reason(v.verifyDsse(p384.bundle, p384.key))).toBe("bundle-too-large");
    });

    it("rejects bytes one byte over the limit", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      expect(await reason(v.verifyDsse(new TextEncoder().encode(p384.bundle), p384.key))).toBe("bundle-too-large");
    });

    it("accepts a bundle of exactly the limit", async () => {
      const v = await withLimit(p384.bundle.length);
      expect(await reason(v.verifyDsse(p384.bundle, p384.key))).toBe("accept");
    });

    // 400 two-byte characters exceed a limit only 100 above the text's UTF-16 length.
    it("counts multi-byte characters as their UTF-8 length", async () => {
      const padded = p384.bundle.replace('"mediaType"', `"x": "${"é".repeat(400)}", "mediaType"`);
      const v = await withLimit(padded.length + 100);
      expect(await reason(v.verifyDsse(padded, p384.key))).toBe("bundle-too-large");
    });

    it("rejects bytes that are not UTF-8 as bundle-malformed", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      expect(await reason(v.verifyDsse(new Uint8Array([0x7b, 0xff, 0x7d]), p384.key))).toBe("bundle-malformed");
    });
  });

  describe("log entry rules", () => {
    const twoEntries = changed((b) => {
      const entries = b.verificationMaterial.tlogEntries;
      entries.push(structuredClone(entries[0]));
    });
    const noEntries = changed((b) => {
      b.verificationMaterial.tlogEntries = [];
    });
    // An entry naming a log outside the trusted root is ignored by default (then too few logs
    // verify), and rejected when checkpoints are bound to the entry's log.
    const unknownLog = changed((b) => {
      b.verificationMaterial.tlogEntries[0].logId.keyId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    });

    it.each([
      { name: "a second entry", profile: "strict", options: STRICT, bundle: twoEntries, expected: "tlog-entry-count" },
      { name: "a second entry", profile: "default", options: DEFAULTS, bundle: twoEntries, expected: "accept" },
      { name: "no entries", profile: "strict", options: STRICT, bundle: noEntries, expected: "tlog-entry-count" },
      { name: "no entries", profile: "default", options: DEFAULTS, bundle: noEntries, expected: "bundle-malformed" },
      { name: "an unknown log", profile: "strict", options: STRICT, bundle: unknownLog, expected: "tlog-unknown-log" },
      { name: "an unknown log", profile: "default", options: DEFAULTS, bundle: unknownLog, expected: "tlog-threshold" },
    ])("gives $expected for $name ($profile)", async ({ options, bundle, expected }) => {
      expect(await reason((await verifier(options)).verifyDsse(bundle, p384.key))).toBe(expected);
    });
  });

  describe("trusted root", () => {
    it("ignores keys it cannot load when the entry does not need them", async () => {
      const v = await verifier(STRICT, rootWithUnusableKeys());
      expect(await reason(v.verifyDsse(p384.bundle, p384.key))).toBe("accept");
    });

    it("differs from the certificate flow's loader, which rejects that root as a whole", async () => {
      await expect(new SigstoreVerifier().loadSigstoreRoot(rootWithUnusableKeys())).rejects.toThrow();
    });

    it("fails an entry whose log key cannot be loaded", async () => {
      const root = JSON.parse(p384.root);
      const entryLog = root.tlogs.find((l: Json) => l.baseUrl.includes("log2025-1"));
      entryLog.publicKey.rawBytes = "AAAA";

      const v = await verifier(STRICT, root);
      expect(await reason(v.verifyDsse(p384.bundle, p384.key))).toBe("tlog-log-key-unsupported");
    });
  });

  describe("options", () => {
    const numericOptions = ["tlogThreshold", "tsaThreshold", "maxBundleBytes"] as const;
    const invalidNumbers = [-1, 0.5, NaN, Infinity];

    it.each(numericOptions.flatMap((key) => invalidNumbers.map((value) => ({ key, value }))))(
      "rejects $key = $value",
      ({ key, value }) => {
        expect(() => new ManagedKeyVerifier({ [key]: value })).toThrow("non-negative safe integer");
      },
    );

    it("rejects an empty bundleVersions list", () => {
      expect(() => new ManagedKeyVerifier({ bundleVersions: [] })).toThrow("bundleVersions");
    });

    it("rejects an unknown bundle version", () => {
      expect(() => new ManagedKeyVerifier({ bundleVersions: ["0.4"] })).toThrow("bundleVersions");
    });

    it("freezes the strict profile", () => {
      expect(Object.isFrozen(STRICT_MANAGED_KEY_PROFILE)).toBe(true);
    });

    it("needs a trusted root", async () => {
      await expect(new ManagedKeyVerifier().verifyDsse(p384.bundle, p384.key)).rejects.toThrow("Trusted root is not loaded");
    });
  });
});
