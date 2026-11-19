/*
 * Managed-key bundle verification.
 *
 * Verifies bundles signed with a long-lived key the caller already trusts
 * (for example a cloud KMS key used through `cosign attest-blob --key`),
 * instead of a Fulcio certificate. The caller's key is the only key used:
 * the bundle's publicKey.hint is never used to find or install one, and there
 * is no certificate, issuer or workflow fallback.
 *
 * Transparency log, checkpoint, timestamp and body checks reuse the modules of
 * the certificate flow. By default the checks match that flow's posture; the
 * options below enable a stricter profile (STRICT_MANAGED_KEY_PROFILE).
 */
import { base64ToUint8Array, digest as digestBytes, importKey, sha256, stringToUint8Array, uint8ArrayEqual, Uint8ArrayToHex, Uint8ArrayToString, verifySignature, } from "@freedomofpress/crypto-browser";
import { assertBundle } from "./bundle.js";
import { preAuthEncoding } from "./dsse.js";
import { fail, VerificationError } from "./errors.js";
import { parseValidityPeriod } from "./interfaces.js";
import { findDuplicateKey } from "./json.js";
import { ManagedPublicKey } from "./key.js";
import { BUNDLE_VERSIONS, countOperators, getBundleVersion } from "./sigstore.js";
import { verifyBundleTimestampForSignature } from "./timestamp/tsa.js";
import { verifyTLogBody } from "./tlog/body.js";
import { LogCheckpoint, SignedNote } from "./tlog/checkpoint.js";
import { verifyMerkleInclusion } from "./tlog/merkle.js";
import { verifyInclusionPromise } from "./tlog/set.js";
import { TrustedRootProvider } from "./trust/tuf.js";
import { X509Certificate } from "./x509/index.js";
const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
// Same bounds as the certificate flow.
const MAX_SUBJECTS = 1024;
const MAX_SUBJECT_DIGESTS = 32;
const DEFAULT_MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
// Copies an options object, lists included, and freezes the copy, so a verifier keeps the options it
// was built with even if the caller mutates theirs (or the exported preset) afterwards.
function freezeOptions(options) {
    const copy = { ...options };
    if (copy.bundleVersions !== undefined) {
        copy.bundleVersions = Object.freeze([...copy.bundleVersions]);
    }
    if (copy.allowedEntryKinds !== undefined) {
        copy.allowedEntryKinds = Object.freeze([...copy.allowedEntryKinds]);
    }
    return Object.freeze(copy);
}
/**
 * Strict profile: the canonical v0.3 media type, unambiguous JSON, exactly one Rekor v2
 * hashedrekord entry without Rekor v1 metadata, exactly one RFC 3161 timestamp, and checkpoints
 * bound to the entry's log. It applies to DSSE and messageSignature content alike and places no
 * restriction on the content type. The object and its lists are frozen.
 */
export const STRICT_MANAGED_KEY_PROFILE = freezeOptions({
    bundleVersions: ["0.3"],
    requireCanonicalMediaType: true,
    rejectDuplicateKeys: true,
    requireSingleTlogEntry: true,
    allowedEntryKinds: ["hashedrekord/0.0.2"],
    rejectIntegratedTime: true,
    rejectInclusionPromise: true,
    requireSingleTimestamp: true,
    checkpointOriginBinding: true,
});
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const present = (o, key) => isObj(o) && o[key] !== undefined;
function errorMessage(error) {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
// Runs one verification step; an error that carries no reason code gets `code`.
async function step(code, fn) {
    try {
        return await fn();
    }
    catch (e) {
        if (e instanceof VerificationError) {
            throw e;
        }
        const message = errorMessage(e);
        fail(code, message);
    }
}
// Whether `text` is longer than `limit` bytes as UTF-8. Each UTF-16 code unit encodes to between one
// and three bytes, so the text is only encoded when its length alone does not decide.
function exceedsUtf8Bytes(text, limit) {
    if (text.length > limit) {
        return true;
    }
    if (text.length * 3 <= limit) {
        return false;
    }
    return new TextEncoder().encode(text).length > limit;
}
// A trusted root log, or undefined when it has no usable log ID. A log whose key or validity period
// cannot be loaded is kept with the error, so that only its own entries fail.
async function loadTrustedLog(log) {
    let logId;
    try {
        if (!isObj(log) || typeof log.logId?.keyId !== "string") {
            return undefined;
        }
        logId = base64ToUint8Array(log.logId.keyId);
    }
    catch {
        return undefined;
    }
    try {
        const { keyDetails, rawBytes } = log.publicKey ?? {};
        if (typeof keyDetails !== "string" || typeof rawBytes !== "string") {
            throw new Error("missing public key");
        }
        return {
            logId,
            baseUrl: log.baseUrl,
            key: {
                publicKey: await importKey(keyDetails, keyDetails, rawBytes),
                logId,
                hashAlgorithm: typeof log.hashAlgorithm === "string" ? log.hashAlgorithm : "",
                operator: typeof log.operator === "string" ? log.operator : "",
                validFor: parseValidityPeriod(log.publicKey.validFor),
            },
        };
    }
    catch (e) {
        const error = errorMessage(e);
        return { logId, baseUrl: log.baseUrl, error };
    }
}
// A timestamp authority with a valid validity period and a parseable, non-empty certificate chain.
function isLoadableAuthority(ca) {
    try {
        if (!isObj(ca)) {
            return false;
        }
        parseValidityPeriod(ca.validFor);
        const certs = ca.certChain?.certificates;
        if (!Array.isArray(certs) || certs.length === 0) {
            return false;
        }
        for (const certificate of certs) {
            const bytes = base64ToUint8Array(certificate.rawBytes);
            X509Certificate.parse(bytes);
        }
        return true;
    }
    catch {
        return false;
    }
}
// The origin a Rekor v2 log signs checkpoints under: the host of its base URL, as sigstore-go derives it.
function logOrigin(baseUrl) {
    if (typeof baseUrl !== "string") {
        return undefined;
    }
    try {
        const url = new URL(baseUrl);
        const isHttp = url.protocol === "https:" || url.protocol === "http:";
        const hasCredentials = url.username || url.password;
        if (!isHttp || hasCredentials || !url.hostname) {
            return undefined;
        }
        return url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
    }
    catch {
        return undefined;
    }
}
// verifyBundle has already required an envelope for "dsse" content; this narrows the type.
function dsseEnvelope(bundle) {
    if (!bundle.dsseEnvelope) {
        fail("content-unsupported", "Bundle does not contain a DSSE envelope");
    }
    return bundle.dsseEnvelope;
}
// At most one variant of each oneof: the content, and the verification material.
function checkSingleVariants(bundle) {
    const material = bundle.verificationMaterial;
    const contentVariants = ["messageSignature", "dsseEnvelope"];
    const materialVariants = ["publicKey", "certificate", "x509CertificateChain"];
    const contentCount = contentVariants.filter((kind) => present(bundle, kind)).length;
    const materialCount = materialVariants.filter((kind) => present(material, kind)).length;
    if (contentCount > 1 || materialCount > 1) {
        fail("conflicting-oneof", "Bundle has more than one variant of its content or verification material");
    }
}
// publicKey verification material, and content of the kind the caller verifies.
function checkManagedKeyContent(bundle, content) {
    const material = bundle.verificationMaterial;
    if (!isObj(material) || !isObj(material.publicKey)) {
        fail("verification-material-unsupported", "Managed-key verification needs a bundle with publicKey verification material");
    }
    const env = bundle.dsseEnvelope;
    const hasDsse = isObj(env) && Array.isArray(env.signatures) && env.signatures.length === 1;
    const hasMessageSignature = content === "artifact" && isObj(bundle.messageSignature);
    if (hasDsse || hasMessageSignature) {
        return;
    }
    if (content === "dsse") {
        fail("content-unsupported", "Bundle must contain a DSSE envelope with exactly one signature");
    }
    fail("content-unsupported", "Bundle must contain a messageSignature or a DSSE envelope with exactly one signature");
}
function isRekorV2Entry(entry) {
    const { kind, version } = entry.kindVersion;
    return (kind === "hashedrekord" || kind === "dsse") && version === "0.0.2";
}
export class ManagedKeyVerifier {
    constructor(options = {}) {
        this.timestampAuthorities = [];
        this.options = freezeOptions(options);
        this.bundleVersions = [...(options.bundleVersions ?? ["0.2", "0.3"])];
        const hasUnknownVersion = this.bundleVersions.some((version) => !BUNDLE_VERSIONS.includes(version));
        if (!this.bundleVersions.length || hasUnknownVersion) {
            const supportedVersions = BUNDLE_VERSIONS.join(", ");
            throw new Error(`bundleVersions must be a non-empty subset of ${supportedVersions}`);
        }
        this.tlogThreshold = options.tlogThreshold ?? 1;
        this.tsaThreshold = options.tsaThreshold ?? 0;
        this.maxBundleBytes = options.maxBundleBytes ?? DEFAULT_MAX_BUNDLE_BYTES;
        for (const [name, value] of Object.entries({
            tlogThreshold: this.tlogThreshold,
            tsaThreshold: this.tsaThreshold,
            maxBundleBytes: this.maxBundleBytes,
        })) {
            if (!Number.isSafeInteger(value) || value < 0) {
                throw new Error(`${name} must be a non-negative safe integer`);
            }
        }
    }
    /**
     * Loads the transparency logs and timestamp authorities of a trusted root. Each log key and each
     * authority is loaded on its own: one that is unsupported (for example an Ed25519 key on a runtime
     * without Ed25519 and without the fallback), malformed or expired does not stop verification of
     * entries and timestamps that do not use it. Fulcio CAs and CT logs are not used.
     */
    async loadTrustedRoot(root) {
        if (!isObj(root)) {
            throw new Error("Trusted root must be an object");
        }
        const tlogs = Array.isArray(root.tlogs) ? root.tlogs : [];
        const logs = await Promise.all(tlogs.map(loadTrustedLog));
        const authorities = Array.isArray(root.timestampAuthorities) ? root.timestampAuthorities : [];
        this.timestampAuthorities = authorities.filter(isLoadableAuthority);
        this.logs = logs.filter((l) => l !== undefined);
    }
    /** Loads the trusted root through TUF (Sigstore's production repository by default). */
    async loadTrustedRootWithTUF(tufProvider) {
        const provider = tufProvider || new TrustedRootProvider();
        await this.loadTrustedRoot(await provider.getTrustedRoot());
    }
    /**
     * Verifies a DSSE bundle signed with `publicKey` and returns its payload. The caller checks the
     * payload (for example the in-toto statement's subject and predicate). A bundle or key that fails
     * verification throws a VerificationError whose `code` is one of REASON_CODES; calling it before a
     * trusted root is loaded, or with a parsed bundle under rejectDuplicateKeys, throws other errors.
     *
     * @param publicKey PEM "PUBLIC KEY" or DER SubjectPublicKeyInfo of an ECDSA P-256 or P-384 key.
     */
    async verifyDsse(bundle, publicKey) {
        const key = ManagedPublicKey.from(publicKey);
        const verified = await this.verifyBundle(bundle, key, "dsse", (parsed) => this.verifyDsseSignature(dsseEnvelope(parsed), key));
        const env = dsseEnvelope(verified.bundle);
        return {
            payloadType: env.payloadType,
            payload: base64ToUint8Array(env.payload),
            timestamps: verified.timestamps,
        };
    }
    /**
     * Verifies a bundle signed with `publicKey` over `data`: a messageSignature over the artifact, or a
     * DSSE in-toto statement with a subject whose SHA-256 is the artifact's. With `isDigestOnly`, `data`
     * is the artifact's digest: its SHA-256 digest for a DSSE statement, or the digest the key implies
     * for a messageSignature (SHA-256 for P-256, SHA-384 for P-384).
     */
    async verifyArtifact(bundle, publicKey, data, isDigestOnly = false) {
        const key = ManagedPublicKey.from(publicKey);
        await this.verifyBundle(bundle, key, "artifact", async (parsed) => {
            if (isDigestOnly) {
                const isDsse = Boolean(parsed.dsseEnvelope);
                const expected = isDsse ? 32 : key.digestLength;
                if (data.byteLength !== expected) {
                    if (isDsse) {
                        throw new Error("SHA-256 digest must be exactly 32 bytes");
                    }
                    throw new Error(`${key.hash} digest must be exactly ${expected} bytes`);
                }
            }
            if (parsed.dsseEnvelope) {
                await this.verifyDsseSignature(parsed.dsseEnvelope, key);
                await this.verifySubject(parsed.dsseEnvelope, data, isDigestOnly);
            }
            else {
                await this.verifyMessageSignature(parsed.messageSignature, key, data, isDigestOnly);
            }
        });
        return true;
    }
    async verifyDsseSignature(env, key) {
        const verified = await step("dsse-signature-invalid", async () => {
            const publicKey = await key.publicKey;
            const payload = base64ToUint8Array(env.payload);
            const encodedPayload = preAuthEncoding(env.payloadType, payload);
            const signature = base64ToUint8Array(env.signatures[0].sig);
            return verifySignature(publicKey, encodedPayload, signature, key.hash);
        });
        if (!verified) {
            fail("dsse-signature-invalid", "DSSE signature verification failed");
        }
    }
    async verifySubject(env, data, isDigestOnly) {
        if (env.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
            fail("payload-type-unsupported", `Unsupported DSSE payload type: ${env.payloadType}`);
        }
        const statement = await step("artifact-mismatch", () => {
            const payload = base64ToUint8Array(env.payload);
            const text = Uint8ArrayToString(payload);
            return JSON.parse(text);
        });
        const subjects = statement?.subject;
        if (!Array.isArray(subjects) || subjects.length === 0 || subjects.length > MAX_SUBJECTS) {
            fail("artifact-mismatch", `DSSE payload must have between 1 and ${MAX_SUBJECTS} subjects`);
        }
        const digest = isDigestOnly ? data : await sha256(data);
        const artifactDigest = Uint8ArrayToHex(digest);
        let matched = false;
        for (const subject of subjects) {
            const digests = isObj(subject) ? subject.digest : undefined;
            if (!isObj(digests) || Object.keys(digests).length > MAX_SUBJECT_DIGESTS) {
                fail("artifact-mismatch", `Invalid DSSE subject digest map (maximum ${MAX_SUBJECT_DIGESTS} digests)`);
            }
            matched || (matched = typeof digests.sha256 === "string" && artifactDigest === digests.sha256.toLowerCase());
        }
        if (!matched) {
            fail("artifact-mismatch", `Artifact digest ${artifactDigest} does not match any subject in DSSE payload`);
        }
    }
    async verifyMessageSignature({ messageDigest, signature }, key, data, isDigestOnly) {
        const digest = isDigestOnly ? data : await digestBytes(key.hash, data);
        if (messageDigest.algorithm !== key.digestAlgorithm) {
            fail("artifact-mismatch", "Artifact digest does not match the bundle message digest");
        }
        const bundleDigest = base64ToUint8Array(messageDigest.digest);
        if (!uint8ArrayEqual(digest, bundleDigest)) {
            fail("artifact-mismatch", "Artifact digest does not match the bundle message digest");
        }
        const sig = base64ToUint8Array(signature);
        const cryptoKey = await key.publicKey;
        const { verifyDigest } = this.options;
        let verified;
        if (isDigestOnly) {
            if (!verifyDigest) {
                throw new Error("Digest-only verification needs the verifyDigest option");
            }
            verified = await step("message-signature-invalid", () => verifyDigest(cryptoKey, data, sig));
        }
        else {
            verified = await step("message-signature-invalid", () => verifySignature(cryptoKey, data, sig, key.hash));
        }
        if (!verified) {
            fail("message-signature-invalid", "Artifact signature verification failed");
        }
    }
    // Checks the bundle in the order of the strict profile, so that the first failure (and its reason
    // code) does not depend on the implementation: input, variants and profile rules, structure, then
    // the signature (`verifyContent`), the log entries and the timestamps.
    async verifyBundle(input, key, content, verifyContent) {
        const logs = this.logs;
        if (!logs) {
            throw new Error("Trusted root is not loaded");
        }
        const parsed = await this.parseBundle(input);
        checkSingleVariants(parsed);
        const version = this.bundleVersion(parsed.mediaType);
        checkManagedKeyContent(parsed, content);
        this.checkProfileLimits(parsed.verificationMaterial);
        // Full structural validation, as for certificate bundles.
        await step("bundle-malformed", () => assertBundle(parsed, "publicKey"));
        const bundle = parsed;
        await verifyContent(bundle);
        const integratedTimes = await this.verifyTlogEntries(bundle, key, logs, version !== "0.1");
        const timestamps = await this.verifyTimestamps(bundle);
        if (integratedTimes.length + timestamps.length === 0) {
            fail("timestamp-count", "No verified observer timestamp anchors the signature in time.");
        }
        return { bundle, timestamps };
    }
    // Bounds the input, rejects repeated member names when configured to, and parses it.
    async parseBundle(input) {
        let parsed;
        if (typeof input === "string" || input instanceof Uint8Array) {
            let tooLarge;
            if (typeof input === "string") {
                tooLarge = exceedsUtf8Bytes(input, this.maxBundleBytes);
            }
            else {
                tooLarge = input.byteLength > this.maxBundleBytes;
            }
            if (tooLarge) {
                fail("bundle-too-large", `Bundle is larger than ${this.maxBundleBytes} bytes`);
            }
            let text;
            if (typeof input === "string") {
                text = input;
            }
            else {
                text = await step("bundle-malformed", () => {
                    const decoder = new TextDecoder("utf-8", { fatal: true });
                    return decoder.decode(input);
                });
            }
            if (this.options.rejectDuplicateKeys) {
                const duplicate = await step("bundle-malformed", () => findDuplicateKey(text));
                if (duplicate !== undefined) {
                    fail("duplicate-json-key", `Bundle JSON repeats the member ${duplicate}`);
                }
            }
            parsed = await step("bundle-malformed", () => JSON.parse(text));
        }
        else {
            if (this.options.rejectDuplicateKeys) {
                throw new TypeError("rejectDuplicateKeys needs the bundle as JSON text or bytes");
            }
            parsed = input;
        }
        if (!isObj(parsed)) {
            fail("bundle-malformed", "Bundle is not a JSON object");
        }
        return parsed;
    }
    // The bundle version named by an enabled media type, in the canonical spelling if that is required.
    bundleVersion(mediaType) {
        let version;
        try {
            const spelling = typeof mediaType === "string" ? mediaType : "";
            version = getBundleVersion(spelling, this.bundleVersions);
        }
        catch {
            fail("media-type-unsupported", `Unsupported bundle media type: ${String(mediaType)}`);
        }
        const canonicalMediaType = `application/vnd.dev.sigstore.bundle.v${version}+json`;
        if (this.options.requireCanonicalMediaType && mediaType !== canonicalMediaType) {
            fail("media-type-unsupported", `Bundle media type must be spelled ${canonicalMediaType}`);
        }
        return version;
    }
    // Transparency log entry and timestamp counts, entry kinds and Rekor v1 metadata.
    checkProfileLimits(material) {
        const opts = this.options;
        const entries = Array.isArray(material.tlogEntries) ? material.tlogEntries : [];
        if (opts.requireSingleTlogEntry && entries.length !== 1) {
            fail("tlog-entry-count", `Exactly one transparency log entry is required, found ${entries.length}`);
        }
        for (const entry of entries) {
            const kindVersion = isObj(entry) ? entry.kindVersion : undefined;
            if (opts.allowedEntryKinds) {
                const entryKind = `${kindVersion?.kind}/${kindVersion?.version}`;
                if (!opts.allowedEntryKinds.includes(entryKind)) {
                    fail("tlog-entry-kind", `Transparency log entry kind ${entryKind} is not accepted`);
                }
            }
            if (opts.rejectIntegratedTime && present(entry, "integratedTime")) {
                fail("integrated-time-present", "Transparency log entry must not carry an integratedTime");
            }
            if (opts.rejectInclusionPromise && present(entry, "inclusionPromise")) {
                fail("inclusion-promise-present", "Transparency log entry must not carry an inclusion promise");
            }
        }
        if (opts.requireSingleTimestamp) {
            const data = material.timestampVerificationData;
            const timestamps = isObj(data) ? data.rfc3161Timestamps : undefined;
            if (!Array.isArray(timestamps) || timestamps.length !== 1) {
                fail("timestamp-count", "Exactly one RFC 3161 timestamp is required");
            }
        }
    }
    // Verifies every RFC 3161 timestamp over the bundle signature and returns their times.
    async verifyTimestamps(bundle) {
        let encodedSignature;
        if (bundle.dsseEnvelope) {
            encodedSignature = bundle.dsseEnvelope.signatures[0].sig;
        }
        else {
            encodedSignature = bundle.messageSignature.signature;
        }
        const signature = base64ToUint8Array(encodedSignature);
        const verified = await verifyBundleTimestampForSignature(bundle.verificationMaterial.timestampVerificationData, signature, this.timestampAuthorities);
        const operators = new Set(verified.map((timestamp) => timestamp.operator));
        const tsaOperators = countOperators(operators);
        if (tsaOperators < this.tsaThreshold) {
            fail("timestamp-threshold", `Not enough verified TSA operators: ${tsaOperators} < ${this.tsaThreshold}`);
        }
        return verified.map((t) => t.signingTime);
    }
    // Verifies every entry from a trusted log and returns the integrated times bound by verified SETs.
    async verifyTlogEntries(bundle, key, logs, requireProof) {
        const operators = new Set();
        const integratedTimes = [];
        for (const entry of bundle.verificationMaterial.tlogEntries) {
            const logId = base64ToUint8Array(entry.logId.keyId);
            const log = logs.find((l) => uint8ArrayEqual(l.logId, logId));
            if (!log) {
                if (this.options.checkpointOriginBinding) {
                    fail("tlog-unknown-log", `Transparency log ${entry.logId.keyId} is not in the trusted root`);
                }
                continue;
            }
            if (!log.key) {
                const message = `The key of transparency log ${entry.logId.keyId} could not be loaded: ${log.error}`;
                fail("tlog-log-key-unsupported", message);
            }
            const logKey = log.key;
            const promise = entry.inclusionPromise?.signedEntryTimestamp;
            if (!entry.inclusionProof && (requireProof || !promise)) {
                fail("inclusion-proof-missing", "Transparency log entry requires an inclusion proof.");
            }
            if (promise) {
                const integratedTime = await step("inclusion-promise-invalid", () => verifyInclusionPromise(entry, promise, logKey));
                integratedTimes.push(integratedTime);
            }
            await step("tlog-entry-malformed", () => verifyTLogBody(entry, bundle, key));
            if (entry.inclusionProof) {
                await this.verifyInclusion(entry, entry.inclusionProof, log, logKey);
            }
            operators.add(logKey.operator);
        }
        const verifiedOperators = countOperators(operators);
        if (verifiedOperators < this.tlogThreshold) {
            fail("tlog-threshold", `Not enough verified transparency logs: ${verifiedOperators} < ${this.tlogThreshold}`);
        }
        return integratedTimes;
    }
    // Inclusion proof up to the checkpoint's root, then the checkpoint: origin (if bound) and the entry's
    // log signature. Signature lines from other keys, such as witness cosignatures, are ignored.
    async verifyInclusion(entry, proof, log, logKey) {
        const { note, checkpoint } = await step("checkpoint-malformed", () => {
            const note = SignedNote.fromString(proof.checkpoint.envelope);
            return { note, checkpoint: LogCheckpoint.fromString(note.note) };
        });
        const sameTreeSize = checkpoint.logSize === BigInt(proof.treeSize);
        // Decode the hash only after the size matches, preserving malformed-input errors.
        const sameRootHash = sameTreeSize && uint8ArrayEqual(checkpoint.logHash, base64ToUint8Array(proof.rootHash));
        if (!sameRootHash) {
            fail("inclusion-proof-invalid", "Checkpoint does not match inclusion proof");
        }
        await step("inclusion-proof-invalid", () => verifyMerkleInclusion(entry));
        let origin;
        if (this.options.checkpointOriginBinding && isRekorV2Entry(entry)) {
            origin = logOrigin(log.baseUrl);
            if (origin === undefined || checkpoint.origin !== origin) {
                const checkpointOrigin = JSON.stringify(checkpoint.origin);
                const expectedOrigin = JSON.stringify(origin ?? log.baseUrl);
                const message = `Checkpoint origin ${checkpointOrigin} does not match the entry's log ${expectedOrigin}`;
                fail("checkpoint-origin-mismatch", message);
            }
        }
        const data = stringToUint8Array(note.note);
        for (const sig of note.signatures) {
            const expectedKeyHint = logKey.logId.subarray(0, 4);
            const sameKeyHint = uint8ArrayEqual(sig.keyHint, expectedKeyHint);
            const sameOrigin = origin === undefined || sig.name === origin;
            if (!sameKeyHint || !sameOrigin) {
                continue;
            }
            const verified = await verifySignature(logKey.publicKey, data, sig.signature, logKey.hashAlgorithm)
                .catch(() => false);
            if (verified) {
                return;
            }
        }
        fail("checkpoint-signature-invalid", `Checkpoint has no valid signature from the entry's log ${entry.logId.keyId}`);
    }
}
//# sourceMappingURL=managed.js.map