import { SigstoreBundle } from "./bundle.js";
import { TrustedRoot } from "./interfaces.js";
import { TrustedRootProvider } from "./trust/tuf.js";
export interface ManagedKeyVerifierOptions {
    /** Distinct log operators whose entries must verify (default 1). */
    tlogThreshold?: number;
    /** Distinct timestamp authority operators whose timestamps must verify (default 0). */
    tsaThreshold?: number;
    /** Bundle versions to accept (default ["0.2", "0.3"], as for certificates). */
    bundleVersions?: readonly string[];
    /** Needed only to verify a messageSignature over a digest: verifySignatureOverDigest from "@freedomofpress/crypto-browser/noble". */
    verifyDigest?: (key: CryptoKey, digest: Uint8Array, signature: Uint8Array) => Promise<boolean>;
    /** Largest bundle accepted as JSON text or bytes, checked before parsing (default 16 MiB). */
    maxBundleBytes?: number;
    /**
     * Accept only the canonical media type spelling, application/vnd.dev.sigstore.bundle.vX.Y+json,
     * not the legacy application/vnd.dev.sigstore.bundle+json;version=X.Y.
     */
    requireCanonicalMediaType?: boolean;
    /** Reject JSON that repeats a member name in any object. The bundle must then be passed as text or bytes. */
    rejectDuplicateKeys?: boolean;
    /** Require exactly one transparency log entry; an additional entry fails, with or without its own proof. */
    requireSingleTlogEntry?: boolean;
    /** Entry kinds to accept, as "kind/version" (for example ["hashedrekord/0.0.2"] for Rekor v2 only). */
    allowedEntryKinds?: readonly string[];
    /** Reject entries with an integratedTime member, whatever its value. Rekor v2 sets none. */
    rejectIntegratedTime?: boolean;
    /** Reject entries with an inclusionPromise (SET) member. Rekor v2 issues none. */
    rejectInclusionPromise?: boolean;
    /** Require exactly one RFC 3161 timestamp. By default any number may be present, and all must verify. */
    requireSingleTimestamp?: boolean;
    /**
     * For Rekor v2 entries, require the checkpoint origin, and the name on the log's signature line, to
     * be the host of the entry's log's baseUrl in the trusted root. Entries naming a log outside the
     * trusted root are rejected instead of ignored. (The checkpoint must always be signed by the
     * entry's own log key.)
     */
    checkpointOriginBinding?: boolean;
}
/**
 * Strict profile: the canonical v0.3 media type, unambiguous JSON, exactly one Rekor v2
 * hashedrekord entry without Rekor v1 metadata, exactly one RFC 3161 timestamp, and checkpoints
 * bound to the entry's log. It applies to DSSE and messageSignature content alike and places no
 * restriction on the content type. The object and its lists are frozen.
 */
export declare const STRICT_MANAGED_KEY_PROFILE: Readonly<ManagedKeyVerifierOptions>;
export interface ManagedKeyDsseResult {
    payloadType: string;
    payload: Uint8Array;
    /** Times from the verified RFC 3161 timestamps. */
    timestamps: Date[];
}
/** A bundle as JSON text, UTF-8 bytes, or an already parsed object (not with rejectDuplicateKeys). */
export type BundleInput = string | Uint8Array | SigstoreBundle;
export declare class ManagedKeyVerifier {
    private readonly options;
    private readonly tlogThreshold;
    private readonly tsaThreshold;
    private readonly bundleVersions;
    private readonly maxBundleBytes;
    private logs;
    private timestampAuthorities;
    constructor(options?: ManagedKeyVerifierOptions);
    /**
     * Loads the transparency logs and timestamp authorities of a trusted root. Each log key and each
     * authority is loaded on its own: one that is unsupported (for example an Ed25519 key on a runtime
     * without Ed25519 and without the fallback), malformed or expired does not stop verification of
     * entries and timestamps that do not use it. Fulcio CAs and CT logs are not used.
     */
    loadTrustedRoot(root: TrustedRoot): Promise<void>;
    /** Loads the trusted root through TUF (Sigstore's production repository by default). */
    loadTrustedRootWithTUF(tufProvider?: TrustedRootProvider): Promise<void>;
    /**
     * Verifies a DSSE bundle signed with `publicKey` and returns its payload. The caller checks the
     * payload (for example the in-toto statement's subject and predicate). A bundle or key that fails
     * verification throws a VerificationError whose `code` is one of REASON_CODES; calling it before a
     * trusted root is loaded, or with a parsed bundle under rejectDuplicateKeys, throws other errors.
     *
     * @param publicKey PEM "PUBLIC KEY" or DER SubjectPublicKeyInfo of an ECDSA P-256 or P-384 key.
     */
    verifyDsse(bundle: BundleInput, publicKey: string | Uint8Array): Promise<ManagedKeyDsseResult>;
    /**
     * Verifies a bundle signed with `publicKey` over `data`: a messageSignature over the artifact, or a
     * DSSE in-toto statement with a subject whose SHA-256 is the artifact's. With `isDigestOnly`, `data`
     * is the artifact's digest: its SHA-256 digest for a DSSE statement, or the digest the key implies
     * for a messageSignature (SHA-256 for P-256, SHA-384 for P-384).
     */
    verifyArtifact(bundle: BundleInput, publicKey: string | Uint8Array, data: Uint8Array, isDigestOnly?: boolean): Promise<true>;
    private verifyDsseSignature;
    private verifySubject;
    private verifyMessageSignature;
    private verifyBundle;
    private parseBundle;
    private bundleVersion;
    private checkProfileLimits;
    private verifyTimestamps;
    private verifyTlogEntries;
    private verifyInclusion;
}
