const isStr = (v) => typeof v === "string";
// Bound the aggregate encoded data this verifier will decode, parse, or hash.
const MAX_BUNDLE_STRING_CHARS = 16 * 1024 * 1024;
function boundedStrings() {
    let total = 0;
    return (v) => {
        if (!isStr(v))
            return false;
        total += v.length;
        return total <= MAX_BUNDLE_STRING_CHARS;
    };
}
// Protobuf log indices, tree sizes and times are non-negative int64 values.
// Bound the string before BigInt conversion to avoid unbounded arithmetic.
const isInt64 = (v) => isStr(v) && /^\d{1,19}$/.test(v) && BigInt(v) <= 9223372036854775807n;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isObj = (v) => typeof v === "object" && v !== null;
function check(cond, what) {
    if (!cond)
        throw new Error(`Invalid bundle: ${what}`);
}
function checkTimestampVerificationData(data, isBoundedStr) {
    if (data == null)
        return;
    check(isObj(data), "timestampVerificationData");
    const ts = data.rfc3161Timestamps;
    check(ts === undefined || (Array.isArray(ts) && ts.length <= 32 && ts.every((t) => isObj(t) && isBoundedStr(t.signedTimestamp))), "rfc3161Timestamps");
}
// Lives in verifyBundleTimestamp(), which every caller routes through.
export function assertTimestampVerificationData(data) {
    checkTimestampVerificationData(data, boundedStrings());
}
// Structural validation of a parsed bundle, replacing the compile-time-only type with runtime checks.
// Entry count is capped at 32 like sigstore-go does. `material` selects the verification material the
// caller needs: a certificate (the default), or a managed key, which must be the only material present.
export function assertBundle(b, material = "certificate") {
    const isBoundedStr = boundedStrings();
    check(isObj(b) && isBoundedStr(b.mediaType) && isObj(b.verificationMaterial), "missing mediaType or verificationMaterial");
    const vm = b.verificationMaterial;
    if (material === "publicKey") {
        const hasCertificate = vm.certificate !== undefined || vm.x509CertificateChain !== undefined;
        const hasPublicKey = !hasCertificate && isObj(vm.publicKey);
        let hasValidHint = false;
        if (hasPublicKey) {
            const hint = vm.publicKey.hint;
            hasValidHint = hint === undefined || isBoundedStr(hint);
        }
        check(hasValidHint, "publicKey");
    }
    else {
        const certs = vm.certificate ? [vm.certificate] : vm.x509CertificateChain?.certificates;
        check(Array.isArray(certs) && certs.length > 0 && certs.length <= 32 && certs.every((c) => isObj(c) && isBoundedStr(c.rawBytes)), "certificate");
    }
    check(Array.isArray(vm.tlogEntries) && vm.tlogEntries.length > 0 && vm.tlogEntries.length <= 32, "tlogEntries");
    for (const e of vm.tlogEntries) {
        check(isObj(e) && isInt64(e.logIndex) && isBoundedStr(e.logId?.keyId) && isBoundedStr(e.canonicalizedBody), "tlog entry");
        check(isBoundedStr(e.kindVersion?.kind) && isBoundedStr(e.kindVersion?.version), "tlog entry kindVersion");
        check(e.integratedTime == null || (isInt64(e.integratedTime) && Number.isFinite(new Date(Number(e.integratedTime) * 1000).getTime())), "tlog entry integratedTime");
        // A SET signs the integrated time, so a promise without one is malformed.
        // SET canonicalization uses Number, which must not round the signed log index.
        const set = e.inclusionPromise?.signedEntryTimestamp;
        check(e.inclusionPromise === undefined || (isBoundedStr(set) && set !== "" && isInt64(e.integratedTime) && Number.isSafeInteger(Number(e.logIndex))), "inclusion promise");
        const p = e.inclusionProof;
        // An int64-sized tree requires at most 63 sibling hashes.
        check(p === undefined ||
            (isObj(p) && isInt64(p.logIndex) && isInt64(p.treeSize) && isBoundedStr(p.rootHash) &&
                Array.isArray(p.hashes) && p.hashes.length <= 63 && p.hashes.every(isBoundedStr) && isBoundedStr(p.checkpoint?.envelope)), "inclusion proof");
    }
    checkTimestampVerificationData(vm.timestampVerificationData, isBoundedStr);
    const { messageSignature: ms, dsseEnvelope: env } = b;
    check((ms === undefined) !== (env === undefined), "exactly one of messageSignature or dsseEnvelope");
    if (ms !== undefined) {
        check(isObj(ms) && isBoundedStr(ms.signature) && isBoundedStr(ms.messageDigest?.algorithm) && isBoundedStr(ms.messageDigest?.digest), "messageSignature");
    }
    else {
        check(isObj(env) && isBoundedStr(env.payload) && isBoundedStr(env.payloadType), "dsseEnvelope");
        check(Array.isArray(env.signatures) && env.signatures.length === 1 && isBoundedStr(env.signatures[0]?.sig), "dsseEnvelope must have exactly one signature");
    }
}
//# sourceMappingURL=bundle.js.map