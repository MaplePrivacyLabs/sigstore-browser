# Vendored test vectors

| Directory | Contents |
| --- | --- |
| `managed-key/` | Managed-key DSSE / Rekor v2 / RFC 3161 corpus: real Cosign v3.1.4 bundles and single-mutation negatives, with `manifest.json` (expected outcome and reason code per vector), `PROFILE.md` (the strict profile) and the generator |
| `sigstore-conformance/` | `bundle-verify/` from sigstore-conformance v0.0.29, unmodified; its README says how it is run here |

`test/corpus/data.ts` loads both. `test/corpus/check.ts` runs them against the library in
`src/managed.corpus.browser.test.ts` (browsers and Node) and `test/runtime-matrix.ts` (the built
`dist/` on Node and Bun); `src/managed*.browser.test.ts` also take fixtures from `managed-key/`.

## The managed-key corpus

`managed-key/` is copied byte for byte from `test-vectors/managed-key` in
<https://github.com/MaplePrivacyLabs/sigstore-rust>, a sigstore-rust fork that holds the original,
at commit `b46a60a32c856d6964f60c23cb78aedee532e2aa`. Paths in `managed-key/README.md` that name
Rust files refer to that repository, and "this library" there means sigstore-rust. Do not edit the
directory here. To compare it with its source and check that it regenerates (Python 3 and the
OpenSSL 3.2+ command line):

```sh
git clone https://github.com/MaplePrivacyLabs/sigstore-rust
git -C sigstore-rust checkout b46a60a32c856d6964f60c23cb78aedee532e2aa
diff -r sigstore-rust/test-vectors/managed-key test/vectors/managed-key
python3 test/vectors/managed-key/generate.py --check
```

Each vector in `manifest.json` records three expectations:

- `profile` is the shared contract: the outcome and reason code under the strict profile of
  `PROFILE.md`. With `STRICT_MANAGED_KEY_PROFILE`, every vector must match it exactly.
- `library` and `library_checkpoint_log_binding` are sigstore-rust's behavior with its default
  options, without and with its checkpoint binding option. They are not requirements for this
  library.

With `ManagedKeyVerifier`'s default options this library follows its own certificate flow, so
twelve vectors differ from sigstore-rust's `library` expectation. `DEFAULT_MODE_DIFFERENCES` in
`test/corpus/check.ts` lists each one with its expected outcome here and the reason.
