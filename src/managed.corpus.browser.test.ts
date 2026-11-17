import { verifySignatureOverDigest } from "@freedomofpress/crypto-browser/noble";
import { describe, expect, inject, it } from "vitest";

import { checkConformance, checkManagedKeyCorpus, type Lib } from "../test/corpus/check.ts";
import * as lib from "./index.js";

// The vendored corpus, shared with sigstore-rust (test/vectors). In the strict profile every vector
// must give the outcome and reason code recorded under "profile" in its manifest.
const corpus = inject("corpus");

describe("managed-key corpus", () => {
  it("is the full corpus, and every reason code it records is one this library reports", () => {
    expect(corpus.managedKey).toHaveLength(44);
    for (const v of corpus.managedKey) {
      for (const expected of Object.values(v.expected)) {
        if (expected.result === "reject") expect(lib.REASON_CODES).toContain(expected.code);
      }
    }
  });

  it("catches a verifier that accepts everything, or rejects for another reason", async () => {
    class AcceptAll {
      async loadTrustedRoot() {}
      async verifyDsse() {}
    }
    class WrongReason extends AcceptAll {
      async verifyDsse() {
        throw new lib.VerificationError("bundle-malformed", "always");
      }
    }
    const rejected = corpus.managedKey.filter((v) => v.expected.profile.result === "reject").length;
    const accepted = corpus.managedKey.length - rejected;
    const acceptAll = await checkManagedKeyCorpus({ ...lib, ManagedKeyVerifier: AcceptAll } as Lib, corpus.managedKey, "strict", "dsse");
    expect(acceptAll).toHaveLength(rejected);
    const wrong = await checkManagedKeyCorpus({ ...lib, ManagedKeyVerifier: WrongReason } as Lib, corpus.managedKey, "strict", "dsse");
    // Every vector, plus each negative whose parent is now rejected.
    expect(wrong.length).toBeGreaterThanOrEqual(rejected + accepted);
  });

  for (const mode of ["strict", "default"] as const) {
    for (const how of ["dsse", "artifact", "digest"] as const) {
      it(`${mode} configuration, ${how}`, async () => {
        expect(await checkManagedKeyCorpus(lib as Lib, corpus.managedKey, mode, how)).toEqual([]);
      });
    }
  }
});

describe("sigstore-conformance v0.0.29 bundle-verify vectors", () => {
  it("pass at the library level, from the artifact and from its digest", async () => {
    expect(corpus.conformance).toHaveLength(67);
    expect(await checkConformance(lib as Lib, corpus.conformance, verifySignatureOverDigest)).toEqual([]);
  });
});
