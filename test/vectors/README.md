# Test vectors shared with sigstore-rust

Both directories come from `test-vectors/` in the sigstore-rust fork that
carries the P-384 Rekor v2 fix, at commit `99db1d6`, exported with `git archive`.
`managed-key/` is byte-identical to that copy, READMEs included; paths in its
README that name Rust files refer to that repository. In
`sigstore-conformance/`, `bundle-verify/` is byte-identical (and identical to
the official release), and the README describes how this repository runs it.

| Directory | Contents | Run here by |
| --- | --- | --- |
| `managed-key/` | Managed-key DSSE / Rekor v2 / RFC 3161 corpus: real Cosign v3.1.4 bundles and single-mutation negatives, with `manifest.json` (expected outcome and language-neutral reason code per vector) and `PROFILE.md` (the strict profile) | `src/managed.corpus.browser.test.ts`, `test/runtime-matrix.ts` (via `test/corpus/check.ts`) |
| `sigstore-conformance/` | sigstore-conformance v0.0.29 (`21533cde`) `test/assets/bundle-verify`, unmodified | the same two files |

Keep the copies identical: to update, re-export them from the sigstore-rust
fork and compare `managed-key/` and `sigstore-conformance/bundle-verify/` with
`diff -r`. Do not edit those files here.
