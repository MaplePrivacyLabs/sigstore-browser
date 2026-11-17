import { describe, expect, inject, it } from "vitest";

// No native Ed25519 and no fallback installed: every Ed25519 key in a trusted root fails to load.
// That must only affect entries of those logs. An entry from an ECDSA log still verifies.
const real = globalThis.crypto.subtle;
const noEd25519 = new Proxy(real, {
  get(target, prop) {
    const value = Reflect.get(target, prop) as unknown;
    if (typeof value !== "function") return value;
    return (...args: unknown[]) => {
      const alg = (prop === "importKey" ? args[2] : args[0]) as { name?: string } | string | undefined;
      if ((typeof alg === "string" ? alg : alg?.name) === "Ed25519") {
        return Promise.reject(new DOMException("Unrecognized name.", "NotSupportedError"));
      }
      return (value as (...a: unknown[]) => unknown).apply(target, args);
    };
  },
});
Object.defineProperty(globalThis.crypto, "subtle", { value: noEd25519, configurable: true });

const corpus = inject("corpus");
const vector = (id: string) => {
  const v = corpus.managedKey.find((x) => x.id === id);
  if (!v) throw new Error(`no vector ${id}`);
  return v;
};

describe("a trusted root with keys this runtime cannot load", () => {
  it("still verifies entries of the logs it can load", async () => {
    const { ManagedKeyVerifier, SigstoreVerifier, VerificationError } = await import("./index.js");
    // Test root: two Ed25519 Rekor v2 logs (unloadable here) and one ECDSA Rekor v1 log.
    const v1 = vector("p384-rekor1-dsse-synthetic");
    const root = JSON.parse(v1.root);
    expect(root.tlogs.filter((l: { publicKey: { keyDetails: string } }) => l.publicKey.keyDetails === "PKIX_ED25519")).toHaveLength(2);

    const verifier = new ManagedKeyVerifier();
    await verifier.loadTrustedRoot(root);
    await expect(verifier.verifyDsse(v1.bundle, v1.key)).resolves.toBeDefined();

    // An entry of an unloadable log fails for that reason, and does not verify.
    const v2 = vector("p384-relogged");
    const error = await verifier.verifyDsse(v2.bundle, v2.key).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as InstanceType<typeof VerificationError>).code).toBe("tlog-log-key-unsupported");

    // The certificate flow's loader cannot load this root at all.
    await expect(new SigstoreVerifier().loadLog(root.tlogs)).rejects.toThrow();
  });
});
