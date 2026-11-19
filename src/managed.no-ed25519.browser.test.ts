import { describe, expect, inject, it } from "vitest";

import { removeNativeEd25519 } from "../test/no-ed25519.ts";

// No native Ed25519 and no fallback installed: every Ed25519 key in a trusted root fails to load.
// That must only affect entries of those logs. An entry from an ECDSA log still verifies.
removeNativeEd25519();

const corpus = inject("corpus");
const vector = (id: string) => {
  const v = corpus.managedKey.find((x) => x.id === id);
  if (!v) {
    throw new Error(`no vector ${id}`);
  }
  return v;
};

describe("a trusted root with keys this runtime cannot load", () => {
  // Test root: two Ed25519 Rekor v2 logs (unloadable here) and one ECDSA Rekor v1 log.
  const rekorV1 = vector("p384-rekor1-dsse-synthetic");
  const root = JSON.parse(rekorV1.root);

  it("has two Ed25519 logs", () => {
    const ed25519Logs = root.tlogs.filter((log: { publicKey: { keyDetails: string } }) => {
      return log.publicKey.keyDetails === "PKIX_ED25519";
    });
    expect(ed25519Logs).toHaveLength(2);
  });

  it("still verifies an entry of the ECDSA log", async () => {
    const { ManagedKeyVerifier } = await import("./index.js");
    const verifier = new ManagedKeyVerifier();
    await verifier.loadTrustedRoot(root);
    await expect(verifier.verifyDsse(rekorV1.bundle, rekorV1.key)).resolves.toBeDefined();
  });

  it("fails an entry of an unloadable log for that reason", async () => {
    const { ManagedKeyVerifier, VerificationError } = await import("./index.js");
    const verifier = new ManagedKeyVerifier();
    await verifier.loadTrustedRoot(root);

    const rekorV2 = vector("p384-relogged");
    const error = await verifier.verifyDsse(rekorV2.bundle, rekorV2.key).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as InstanceType<typeof VerificationError>).code).toBe("tlog-log-key-unsupported");
  });

  it("differs from the certificate flow's loader, which cannot load this root", async () => {
    const { SigstoreVerifier } = await import("./index.js");
    await expect(new SigstoreVerifier().loadLog(root.tlogs)).rejects.toThrow();
  });
});
