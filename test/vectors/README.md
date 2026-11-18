# Vendored test vectors

| Directory | Contents |
| --- | --- |
| `managed-key/` | Managed-key DSSE / Rekor v2 / RFC 3161 corpus: real Cosign v3.1.4 bundles and single-mutation negatives, with `manifest.json` (expected outcome and reason code per vector), `PROFILE.md` (the strict profile) and the generator |
| `sigstore-conformance/` | `bundle-verify/` from sigstore-conformance v0.0.29, unmodified; its README says how it is run here |

`test/corpus/data.ts` loads both. `test/corpus/check.ts` runs them against the library in
`src/managed.corpus.browser.test.ts` (browsers and Node) and `test/runtime-matrix.ts` (the built
`dist/` on Node and Bun); `src/managed*.browser.test.ts` also take fixtures from `managed-key/`.

## The managed-key corpus

The corpus is shared with a sigstore-rust fork, whose copy is the original: `managed-key/` was
exported from that repository's `test-vectors/managed-key` at commit `99db1d6` and is kept
byte-identical to it, READMEs included. Paths in `managed-key/README.md` that name Rust files refer
to that repository, and "this library" there means sigstore-rust. Do not edit the directory here;
re-export it and compare with `diff -r`.

Each vector in `manifest.json` records three expectations:

- `profile` is the shared contract: the outcome and reason code under the strict profile of
  `PROFILE.md`. With `STRICT_MANAGED_KEY_PROFILE`, every vector must match it exactly.
- `library` and `library_checkpoint_log_binding` are sigstore-rust's behaviour with its default
  options, without and with its checkpoint binding option. They are not requirements for this
  library.

With `ManagedKeyVerifier`'s default options this library follows its own certificate flow, so
twelve vectors differ from sigstore-rust's `library` expectation. `DEFAULT_MODE_DIFFERENCES` in
`test/corpus/check.ts` lists each one with its expected outcome here and the reason.
