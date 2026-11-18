# Vendored sigstore-conformance bundle-verification vectors

`bundle-verify/` is an unmodified copy of `test/assets/bundle-verify` from
[sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
at the commit below (release v0.0.29). sigstore-conformance is licensed under
Apache-2.0.

```text
repository: https://github.com/sigstore/sigstore-conformance
commit:     21533cde107c734ebc153c3e3a24d75fc9811a36 (v0.0.29)
path:       test/assets/bundle-verify
```

`src/managed.corpus.browser.test.ts` (in browsers and Node) and
`test/runtime-matrix.ts` (Node and Bun) run every vector through the library API
with `checkConformance` in `test/corpus/check.ts`, following the rules in
`bundle-verify/README.md`: a directory whose name ends in `_fail` must be
rejected, every other one accepted; `key.pub` selects `ManagedKeyVerifier`,
otherwise `SigstoreVerifier` with the `identity` and `issuer` files (or the
suite's defaults); `trusted_root.json` replaces the Sigstore production root
(a snapshot vendored in `../managed-key/sources/trusted_root.production.json`).
Each vector is verified from the artifact bytes and from its SHA-256 digest, with
every bundle version enabled, as the suite's harness does.

This is separate from the `conformance` CI workflow, which still runs the
suite's own harness at v0.0.21 against `dist/cli.js`.

To update, replace `bundle-verify/` with the directory from the new commit,
update the commit above, and check that `diff -r` against a fresh checkout shows
no difference.
