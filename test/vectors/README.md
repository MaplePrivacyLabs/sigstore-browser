# Test vectors shared with sigstore-rust

Both directories are byte-identical copies of `test-vectors/` in the
sigstore-rust fork that carries the P-384 Rekor v2 fix, taken at commit
`99db1d6` with `git archive`. Their own READMEs describe them; paths there that
name Rust files refer to that repository.

| Directory | Contents | Run here by |
| --- | --- | --- |
| `managed-key/` | Managed-key DSSE / Rekor v2 / RFC 3161 corpus: real Cosign v3.1.4 bundles and single-mutation negatives, with `manifest.json` (expected outcome and language-neutral reason code per vector) and `PROFILE.md` (the strict profile) | `src/managed.corpus.test.ts` |
| `sigstore-conformance/` | sigstore-conformance v0.0.29 (`21533cde`) `test/assets/bundle-verify`, unmodified | `src/conformance.test.ts` |

Keep the copies identical: to update, re-export both directories from the
sigstore-rust fork and compare with `diff -r`. Do not edit files here.
