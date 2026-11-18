import { describe, expect, inject, it } from "vitest";

import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { VerificationError } from "./errors.js";
import { ManagedPublicKey } from "./key.js";
import { verifyTLogBody } from "./tlog/body.js";

// Log entry bodies from the vendored corpus, checked directly against a caller's key: the binding
// of the logged key, key details, digest algorithm and length, signature and digest.
const corpus = inject("corpus");
const vector = (id: string): ManagedKeyVector => {
  const v = corpus.managedKey.find((x) => x.id === id);
  if (!v) throw new Error(`no vector ${id}`);
  return v;
};

const p384 = vector("p384-rekor2-dsse-tsa");
const otherP384 = vector("p384-rekor2-dsse-tsa-second-key");
const p256 = vector("p256-rekor2-dsse-tsa");

const BODY_CODES = new Set([
  "tlog-key-mismatch",
  "tlog-key-details-mismatch",
  "tlog-digest-algorithm-mismatch",
  "tlog-digest-malformed",
  "tlog-digest-mismatch",
  "tlog-signature-mismatch",
]);

const base64ToBytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const pemToDer = (pem: string) => base64ToBytes(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""));

// The reason code a check fails with, or "accept".
async function reason(check: () => unknown): Promise<string> {
  try {
    await check();
    return "accept";
  } catch (e) {
    if (e instanceof VerificationError) return e.code;
    throw e;
  }
}

function verifyBody(v: ManagedKeyVector, key = v.key) {
  const bundle = JSON.parse(v.bundle);
  return reason(() => verifyTLogBody(bundle.verificationMaterial.tlogEntries[0], bundle, ManagedPublicKey.from(key)));
}

describe("ManagedPublicKey", () => {
  it("reads a P-384 PEM public key", () => {
    const key = ManagedPublicKey.from(p384.key);
    expect(key.namedCurve).toBe("P-384");
    expect(key.keyDetails).toBe("PKIX_ECDSA_P384_SHA_384");
    expect(key.digestAlgorithm).toBe("SHA2_384");
  });

  it("reads the same key from DER SubjectPublicKeyInfo", () => {
    expect(ManagedPublicKey.from(pemToDer(p384.key)).spki).toEqual(ManagedPublicKey.from(p384.key).spki);
  });

  it("reads a P-256 key", () => {
    const key = ManagedPublicKey.from(p256.key);
    expect(key.namedCurve).toBe("P-256");
    expect(key.digestAlgorithm).toBe("SHA2_256");
  });

  it.each([
    { name: "an empty string", key: "" },
    { name: "a certificate", key: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" },
    { name: "empty bytes", key: new Uint8Array(0) },
    { name: "an Ed25519 key", key: base64ToBytes("MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=") },
  ])("rejects $name as key-unsupported", async ({ key }) => {
    expect(await reason(() => ManagedPublicKey.from(key))).toBe("key-unsupported");
  });
});

describe("transparency log body checks with a managed key", () => {
  it.each(["p384-rekor2-dsse-tsa", "p256-rekor2-dsse-tsa", "p384-rekor1-dsse-synthetic"])(
    "binds the %s entry to its bundle and key",
    async (id) => {
      expect(await verifyBody(vector(id))).toBe("accept");
    },
  );

  it("rejects an entry logged under another key as tlog-key-mismatch", async () => {
    expect(await verifyBody(p384, otherP384.key)).toBe("tlog-key-mismatch");
  });

  // Every corpus vector whose first failing check is a body check fails it here too.
  const bodyNegatives = corpus.managedKey.flatMap((v) => {
    const { profile } = v.expected;
    return profile.result === "reject" && BODY_CODES.has(profile.code) ? [{ id: v.id, code: profile.code, v }] : [];
  });

  it("has corpus vectors for every body check", () => {
    expect(new Set(bodyNegatives.map(({ code }) => code))).toEqual(BODY_CODES);
  });

  it.each(bodyNegatives)("rejects $id as $code", async ({ code, v }) => {
    expect(await verifyBody(v)).toBe(code);
  });
});
