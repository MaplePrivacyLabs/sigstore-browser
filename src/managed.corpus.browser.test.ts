import { verifySignatureOverDigest } from "@freedomofpress/crypto-browser/noble";
import { describe, expect, inject, it } from "vitest";

import { checkConformance, checkManagedKeyCorpus, type How, type Lib, type Mode } from "../test/corpus/check.ts";
import * as lib from "./index.js";

// The vendored corpus, shared with sigstore-rust (test/vectors). In the strict profile every vector
// must give the outcome and reason code recorded under "profile" in its manifest.
const corpus = inject("corpus");

// Stand-ins for ManagedKeyVerifier, to show that the checks fail for a verifier that is wrong.
class AcceptAll {
  async loadTrustedRoot() {}
  async verifyDsse() {}
}
class WrongReason extends AcceptAll {
  async verifyDsse() {
    throw new lib.VerificationError("bundle-malformed", "always");
  }
}
const withVerifier = (verifier: typeof AcceptAll) => ({ ...lib, ManagedKeyVerifier: verifier }) as unknown as Lib;

const CONFIGURATIONS: [Mode, How][] = [
  ["strict", "dsse"],
  ["strict", "artifact"],
  ["strict", "digest"],
  ["default", "dsse"],
  ["default", "artifact"],
  ["default", "digest"],
];

describe("managed-key corpus", () => {
  const rejected = corpus.managedKey.filter((v) => v.expected.profile.result === "reject").length;
  const accepted = corpus.managedKey.length - rejected;

  it("has all 44 vectors", () => {
    expect(corpus.managedKey).toHaveLength(44);
  });

  it("records only reason codes this library reports", () => {
    for (const v of corpus.managedKey) {
      for (const expected of Object.values(v.expected)) {
        if (expected.result === "reject") expect(lib.REASON_CODES).toContain(expected.code);
      }
    }
  });

  it("catches a verifier that accepts everything", async () => {
    const mismatches = await checkManagedKeyCorpus(withVerifier(AcceptAll), corpus.managedKey, "strict", "dsse");
    expect(mismatches).toHaveLength(rejected);
  });

  it("catches a verifier that rejects for another reason", async () => {
    const mismatches = await checkManagedKeyCorpus(withVerifier(WrongReason), corpus.managedKey, "strict", "dsse");
    // Every vector, plus each negative whose parent is now rejected.
    expect(mismatches.length).toBeGreaterThanOrEqual(rejected + accepted);
  });

  it.each(CONFIGURATIONS)("%s configuration, %s", async (mode, how) => {
    expect(await checkManagedKeyCorpus(lib, corpus.managedKey, mode, how)).toEqual([]);
  });
});

describe("sigstore-conformance v0.0.29 bundle-verify vectors", () => {
  it("pass at the library level, from the artifact and from its digest", async () => {
    expect(corpus.conformance).toHaveLength(67);
    expect(await checkConformance(lib, corpus.conformance, verifySignatureOverDigest)).toEqual([]);
  });
});
