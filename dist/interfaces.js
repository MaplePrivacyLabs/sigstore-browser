export function parseValidityPeriod(validity) {
    if (typeof validity?.start !== "string" ||
        (validity.end !== undefined && typeof validity.end !== "string")) {
        throw new Error("Invalid authority validity period");
    }
    const start = new Date(validity.start);
    const end = validity.end === undefined
        ? new Date(8640000000000000)
        : new Date(validity.end);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start > end) {
        throw new Error("Invalid authority validity period");
    }
    return { start, end };
}
export var SigstoreRoots;
(function (SigstoreRoots) {
    SigstoreRoots["certificateAuthorities"] = "certificateAuthorities";
    SigstoreRoots["ctlogs"] = "ctlogs";
    SigstoreRoots["timestampAuthorities"] = "timestampAuthorities";
    SigstoreRoots["tlogs"] = "tlogs";
})(SigstoreRoots || (SigstoreRoots = {}));
// Re-export crypto enums from crypto-browser (shared with tuf-browser)
export { EcdsaTypes, HashAlgorithms, KeyTypes } from "@freedomofpress/crypto-browser";
import { HashAlgorithms } from "@freedomofpress/crypto-browser";
// Supported hash algorithms for payload hash validation
// Rekor v1 uses lowercase (sha256), Rekor v2 uses uppercase with underscore (SHA2_256)
const SUPPORTED_HASH_ALGORITHMS = {
    "sha256": HashAlgorithms.SHA256,
    "sha384": HashAlgorithms.SHA384,
    "sha512": HashAlgorithms.SHA512,
    "SHA2_256": HashAlgorithms.SHA256,
    "SHA2_384": HashAlgorithms.SHA384,
    "SHA2_512": HashAlgorithms.SHA512,
};
export function getHashAlgorithm(algorithm) {
    const hashAlg = SUPPORTED_HASH_ALGORITHMS[algorithm];
    if (!hashAlg) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
    return hashAlg;
}
//# sourceMappingURL=interfaces.js.map