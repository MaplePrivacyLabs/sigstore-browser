import { describe, expect, inject, it } from "vitest";

import type { Lib } from "../test/corpus/check.ts";

// Ed25519 (the Rekor v2 checkpoint signature) through upstream's @noble/curves fallback: WebCrypto is
// made to reject Ed25519, as engines without it do (Safari before 17), before crypto-browser first
// reads crypto.subtle. Then the full corpus and the conformance vectors must give the same results.
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

describe("managed-key verification with the Ed25519 fallback", () => {
  it("verifies the corpus and conformance vectors without native Ed25519", async () => {
    await expect(crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])).rejects.toThrow();
    const noble = await import("@freedomofpress/crypto-browser/noble");
    await noble.installEd25519Fallback();
    const lib = (await import("./index.js")) as unknown as Lib;
    const { checkConformance, checkManagedKeyCorpus } = await import("../test/corpus/check.ts");

    // The Rekor v2 log key really is a fallback key, not a native CryptoKey.
    const verifier = new (lib.ManagedKeyVerifier)();
    await verifier.loadTrustedRoot(JSON.parse(corpus.managedKey[0].root));
    const { importKey } = await import("@freedomofpress/crypto-browser");
    const key = await importKey("PKIX_ED25519", "PKIX_ED25519", "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=");
    expect((key as unknown as { __fallback__?: boolean }).__fallback__).toBe(true);

    for (const mode of ["strict", "default"] as const) {
      expect(await checkManagedKeyCorpus(lib, corpus.managedKey, mode, "dsse")).toEqual([]);
    }
    expect(await checkConformance(lib, corpus.conformance, noble.verifySignatureOverDigest)).toEqual([]);
  });
});
