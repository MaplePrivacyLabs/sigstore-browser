import { describe, expect, inject, it } from "vitest";

import { base64ToBytes } from "../test/corpus/check.ts";
import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { bundle as keylessBundle } from "../test/fixtures/sigstore.js";
import { REASON_CODES, VerificationError } from "./errors.js";
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

const parse = (v: ManagedKeyVector): Json => JSON.parse(v.bundle);
const text = (bundle: unknown) => JSON.stringify(bundle, null, 2);

/** p384's bundle as text, after `change` has modified its parsed form. */
function changed(change: (bundle: Json) => void): string {
  const bundle = parse(p384);
  change(bundle);
  return text(bundle);
}

async function verifier(options: ManagedKeyVerifierOptions = STRICT_MANAGED_KEY_PROFILE, root: Json = JSON.parse(p384.root)) {
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

describe("ManagedKeyVerifier", () => {
  describe("verification", () => {
    it("verifies a P-384 DSSE bundle logged in Rekor v2 with a timestamp, using the caller's key", async () => {
      const v = await verifier();
      const result = await v.verifyDsse(p384.bundle, p384.key);
      expect(result.payloadType).toBe("application/vnd.in-toto+json");
      const statement = JSON.parse(new TextDecoder().decode(result.payload));
      expect(statement._type).toBe("https://in-toto.io/Statement/v1");
      expect(result.timestamps).toHaveLength(1);
      expect(result.timestamps[0].toISOString().slice(0, 10)).toBe(SIGNING_DAY);

      // The same bundle as UTF-8 bytes, and the key as DER.
      await expect(v.verifyDsse(new TextEncoder().encode(p384.bundle), p384.key)).resolves.toBeDefined();
      const der = base64ToBytes(p384.key.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""));
      await expect(v.verifyDsse(p384.bundle, der)).resolves.toBeDefined();

      // A P-256 key.
      await expect((await verifier()).verifyDsse(p256.bundle, p256.key)).resolves.toBeDefined();

      // The artifact against the statement subject.
      await expect(v.verifyArtifact(p384.bundle, p384.key, base64ToBytes(p384.artifact))).resolves.toBe(true);
      expect(await reason(v.verifyArtifact(p384.bundle, p384.key, new Uint8Array([1, 2, 3])))).toBe("artifact-mismatch");
    });
  });

  describe("key authority", () => {
    const UNUSABLE_KEYS: (string | Uint8Array)[] = [
      "",
      "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
      new Uint8Array(0),
    ];
    const ED25519_KEY = "MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=";
    const P521_KEY =
      "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBi44fj79FBp5ZzPNa72pTsvb5XCoFTD6ThQen+AAGN8NEIRXjN5xTE+krQerNc/oLlVAZ/O5rVrI3qdmMzXqgtuAB6JSxfEck6S0RtgG85EgesH5/1aXaFnM9j5H/2j4eccHrB2c6whfZkS39TLg3nJEfV01Z+O3XUl0gmrr5RUpZfAQ=";

    it("uses only the caller's key: the bundle's key hint is never an authority", async () => {
      const v = await verifier();
      const p384Hint = parse(p384).verificationMaterial.publicKey.hint;
      const otherHint = parse(otherP384).verificationMaterial.publicKey.hint;

      // Another real bundle, validly signed and logged under its own key, relabelled with p384's hint.
      const relabelled = parse(otherP384);
      relabelled.verificationMaterial.publicKey.hint = p384Hint;
      expect(await reason(v.verifyDsse(text(relabelled), p384.key))).toBe("dsse-signature-invalid");

      // The hint is not consulted at all: removing or replacing it changes nothing.
      for (const hint of [undefined, "", "not-a-key", otherHint]) {
        const bundle = changed((b) => {
          b.verificationMaterial.publicKey = hint === undefined ? {} : { hint };
        });
        expect(await reason(v.verifyDsse(bundle, p384.key))).toBe("accept");
        expect(await reason(v.verifyDsse(bundle, otherP384.key))).toBe("dsse-signature-invalid");
      }

      // Without a usable caller key there is nothing to verify with.
      for (const key of UNUSABLE_KEYS) {
        expect(await reason(v.verifyDsse(p384.bundle, key))).toBe("key-unsupported");
      }

      // Ed25519 and P-521 keys are not managed-key signers here.
      expect(await reason(v.verifyDsse(p384.bundle, base64ToBytes(ED25519_KEY)))).toBe("key-unsupported");
      expect(await reason(v.verifyDsse(p384.bundle, base64ToBytes(P521_KEY)))).toBe("key-unsupported");
    });
  });

  describe("bundle input", () => {
    it("rejects certificate material, alone or beside the public key", async () => {
      const certificate = keylessBundle().verificationMaterial.certificate;
      expect(certificate?.rawBytes).toBeTruthy();

      for (const options of [STRICT_MANAGED_KEY_PROFILE, {}]) {
        const v = await verifier(options);

        const beside = changed((b) => {
          b.verificationMaterial.certificate = certificate;
        });
        expect(await reason(v.verifyDsse(beside, p384.key))).toBe("conflicting-oneof");

        const chain = changed((b) => {
          delete b.verificationMaterial.publicKey;
          b.verificationMaterial.x509CertificateChain = { certificates: [certificate] };
        });
        expect(await reason(v.verifyDsse(chain, p384.key))).toBe("verification-material-unsupported");

        const alone = changed((b) => {
          delete b.verificationMaterial.publicKey;
          b.verificationMaterial.certificate = certificate;
        });
        expect(await reason(v.verifyDsse(alone, p384.key))).toBe("verification-material-unsupported");
      }
    });

    it("rejects omitted and downgraded media types", async () => {
      const LEGACY_V02 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
      const LEGACY_V03 = "application/vnd.dev.sigstore.bundle+json;version=0.3";
      const CANONICAL_V01 = "application/vnd.dev.sigstore.bundle.v0.1+json";
      const CANONICAL_V02 = "application/vnd.dev.sigstore.bundle.v0.2+json";
      const CANONICAL_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
      const withMediaType = (mediaType: unknown) =>
        changed((b) => {
          if (mediaType === undefined) delete b.mediaType;
          else b.mediaType = mediaType;
        });

      // The strict profile accepts exactly the canonical v0.3 spelling.
      const strict = await verifier();
      const notStrictV03 = [
        undefined,
        null,
        "",
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        CANONICAL_V01,
        LEGACY_V02,
        CANONICAL_V02,
        "application/vnd.dev.sigstore.bundle.v0.4+json",
        LEGACY_V03,
      ];
      for (const mediaType of notStrictV03) {
        expect(await reason(strict.verifyDsse(withMediaType(mediaType), p384.key))).toBe("media-type-unsupported");
      }
      expect(await reason(strict.verifyDsse(withMediaType(CANONICAL_V03), p384.key))).toBe("accept");

      // By default, as for certificate bundles, both spellings of v0.2 and v0.3 are accepted and v0.1 is not.
      const lenient = await verifier({});
      expect(await reason(lenient.verifyDsse(withMediaType(LEGACY_V03), p384.key))).toBe("accept");
      expect(await reason(lenient.verifyDsse(withMediaType(CANONICAL_V02), p384.key))).toBe("accept");
      expect(await reason(lenient.verifyDsse(withMediaType(CANONICAL_V01), p384.key))).toBe("media-type-unsupported");

      // requireCanonicalMediaType alone, with the default versions.
      const canonical = await verifier({ requireCanonicalMediaType: true });
      expect(await reason(canonical.verifyDsse(withMediaType(LEGACY_V03), p384.key))).toBe("media-type-unsupported");
      expect(await reason(canonical.verifyDsse(withMediaType(LEGACY_V02), p384.key))).toBe("media-type-unsupported");
      expect(await reason(canonical.verifyDsse(withMediaType(CANONICAL_V02), p384.key))).toBe("accept");
    });

    it("rejects duplicate JSON member names at any depth before parsing", async () => {
      const v = await verifier();
      const duplicated = {
        topLevel: p384.bundle.replace('"mediaType":', '"mediaType": "x", "mediaType":'),
        escaped: p384.bundle.replace('"mediaType":', '"\\u006dediaType": "x", "mediaType":'),
        nested: p384.bundle.replace('"logIndex":', '"logIndex": "1", "logIndex":'),
      };
      for (const bundle of Object.values(duplicated)) {
        expect(bundle).not.toBe(p384.bundle);
        expect(await reason(v.verifyDsse(bundle, p384.key))).toBe("duplicate-json-key");
      }
      expect(findDuplicateKey(duplicated.nested)).toMatch(/tlogEntries\[0\]\.logIndex$/);
      // The same name in different objects is not a duplicate.
      expect(findDuplicateKey('{"a":[{"b":1},{"b":2}],"c":{"b":3}}')).toBeUndefined();

      // Truncated, and nested deeper than the scanner allows.
      expect(await reason(v.verifyDsse(p384.bundle.slice(0, -10), p384.key))).toBe("bundle-malformed");
      expect(await reason(v.verifyDsse("[".repeat(100) + "]".repeat(100), p384.key))).toBe("bundle-malformed");

      // The check needs the text, so an already parsed object is refused rather than silently unchecked.
      await expect(v.verifyDsse(parse(p384), p384.key)).rejects.toThrow(TypeError);
      // Without the option a parsed object is accepted, as for certificate bundles.
      await expect((await verifier({})).verifyDsse(parse(p384), p384.key)).resolves.toBeDefined();
    });

    it("bounds the input size before parsing", async () => {
      const withLimit = (maxBundleBytes: number) => verifier({ ...STRICT_MANAGED_KEY_PROFILE, maxBundleBytes });

      const oneByteShort = await withLimit(p384.bundle.length - 1);
      expect(await reason(oneByteShort.verifyDsse(p384.bundle, p384.key))).toBe("bundle-too-large");
      expect(await reason(oneByteShort.verifyDsse(new TextEncoder().encode(p384.bundle), p384.key))).toBe("bundle-too-large");
      const exact = await withLimit(p384.bundle.length);
      expect(await reason(exact.verifyDsse(p384.bundle, p384.key))).toBe("accept");

      // Multi-byte characters count as their UTF-8 length: 400 two-byte characters exceed a limit that
      // is only 100 above the text's UTF-16 length.
      const padded = p384.bundle.replace('"mediaType"', `"x": "${"é".repeat(400)}", "mediaType"`);
      const tight = await withLimit(padded.length + 100);
      expect(await reason(tight.verifyDsse(padded, p384.key))).toBe("bundle-too-large");

      // Bytes that are not UTF-8.
      expect(await reason(oneByteShort.verifyDsse(new Uint8Array([0x7b, 0xff, 0x7d]), p384.key))).toBe("bundle-malformed");
    });
  });

  describe("strict profile", () => {
    it("rejects extra or missing log entries and entries from unknown logs only in the strict profile", async () => {
      const strict = await verifier();
      const lenient = await verifier({});

      const twoEntries = changed((b) => {
        const entries = b.verificationMaterial.tlogEntries;
        entries.push(structuredClone(entries[0]));
      });
      expect(await reason(strict.verifyDsse(twoEntries, p384.key))).toBe("tlog-entry-count");
      expect(await reason(lenient.verifyDsse(twoEntries, p384.key))).toBe("accept");

      const noEntries = changed((b) => {
        b.verificationMaterial.tlogEntries = [];
      });
      expect(await reason(strict.verifyDsse(noEntries, p384.key))).toBe("tlog-entry-count");
      expect(await reason(lenient.verifyDsse(noEntries, p384.key))).toBe("bundle-malformed");

      // An entry naming a log outside the trusted root is ignored by default (then too few logs verify)
      // and rejected when checkpoints are bound to the entry's log.
      const unknownLog = changed((b) => {
        b.verificationMaterial.tlogEntries[0].logId.keyId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      });
      expect(await reason(strict.verifyDsse(unknownLog, p384.key))).toBe("tlog-unknown-log");
      expect(await reason(lenient.verifyDsse(unknownLog, p384.key))).toBe("tlog-threshold");
    });
  });

  describe("trusted root", () => {
    it("does not let an unsupported, malformed or retired trusted-root key stop unrelated verification", async () => {
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
        // Retired logs (validity ended) from the real staging root.
        ...stagingRoot.tlogs.filter((l: Json) => l.publicKey.validFor.end),
        "not an object",
      );
      root.ctlogs.push(
        // The staging root's retired RSA CT log key, and a CT key that does not parse.
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

      expect(await reason((await verifier(STRICT_MANAGED_KEY_PROFILE, root)).verifyDsse(p384.bundle, p384.key))).toBe("accept");
      // The certificate flow's loader fails on the same root as a whole.
      await expect(new SigstoreVerifier().loadSigstoreRoot(root)).rejects.toThrow();

      // An entry that does need an unusable key fails, without accepting.
      const broken = JSON.parse(p384.root);
      const entryLog = broken.tlogs.find((l: Json) => l.baseUrl.includes("log2025-1"));
      entryLog.publicKey.rawBytes = "AAAA";
      expect(await reason((await verifier(STRICT_MANAGED_KEY_PROFILE, broken)).verifyDsse(p384.bundle, p384.key))).toBe(
        "tlog-log-key-unsupported",
      );
    });
  });

  describe("setup", () => {
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
      await expect(new ManagedKeyVerifier().verifyDsse(p384.bundle, p384.key)).rejects.toThrow("Trusted root is not loaded");
    });
  });
});
