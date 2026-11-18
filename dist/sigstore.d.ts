import { SigstoreBundle } from "./bundle.js";
import { CertAuthority, CTLog, RawCAs, RawLogs, RekorKeyInfo, TrustedRoot } from "./interfaces.js";
import type { VerificationPolicy } from "./policy.js";
import { TrustedRootProvider } from "./trust/tuf.js";
import { X509Certificate } from "./x509/index.js";
export declare function countOperators(operators: Set<string>): number;
/**
 * Extract bundle version from mediaType string
 * Reference: https://github.com/sigstore/sigstore-go/blob/main/pkg/bundle/bundle.go#L159-L177
 */
export declare const BUNDLE_VERSIONS: string[];
export declare function getBundleVersion(mediaType: string, enabled: readonly string[]): string;
export interface SigstoreVerifierOptions {
    tlogThreshold?: number;
    ctlogThreshold?: number;
    tsaThreshold?: number;
    bundleVersions?: string[];
    verifyDigest?: (key: CryptoKey, digest: Uint8Array, signature: Uint8Array) => Promise<boolean>;
}
export declare class SigstoreVerifier {
    private root;
    private rawRoot;
    private options;
    private bundleVersions;
    private verifyDigest;
    constructor(options?: SigstoreVerifierOptions);
    loadLog(logs: RawLogs): Promise<RekorKeyInfo[]>;
    loadCTLogs(ctlogs: RawLogs): Promise<CTLog[]>;
    verifyCertificateChain(timestamp: Date, leaf: X509Certificate, certificateAuthorities: CertAuthority[]): Promise<X509Certificate[]>;
    loadCA(cas: RawCAs): CertAuthority[];
    loadSigstoreRoot(rawRoot: TrustedRoot): Promise<void>;
    /**
     * Load Sigstore trusted root via TUF
     * Uses The Update Framework for secure, verified updates of trusted root metadata
     *
     * @param tufProvider Optional TrustedRootProvider instance. If not provided, uses default Sigstore TUF repository
     */
    loadSigstoreRootWithTUF(tufProvider?: TrustedRootProvider): Promise<void>;
    verifySCT(cert: X509Certificate, issuer: X509Certificate, ctlogs: CTLog[]): Promise<Set<string>>;
    private verifySET;
    private verifyTlogEntries;
    private verifyBundle;
    verifyArtifactPolicy(policy: VerificationPolicy, bundle: SigstoreBundle, data: Uint8Array, isDigestOnly?: boolean): Promise<boolean>;
    verifyArtifact(identity: string, issuer: string, bundle: SigstoreBundle, data: Uint8Array, isDigestOnly?: boolean): Promise<boolean>;
    /**
     * Verify a DSSE bundle using a verification policy.
     * This matches sigstore-python's verify_dsse API.
     *
     * Reference: https://github.com/sigstore/sigstore-python/blob/main/sigstore/verify/verifier.py#L388
     *
     * Unlike verify_artifact which verifies an artifact against a bundle,
     * this method verifies the DSSE envelope itself and returns the payload.
     * The caller is responsible for checking that the payload matches their
     * expected artifact (e.g., by checking subjects in an in-toto statement).
     *
     * @param bundle - The Sigstore bundle containing the DSSE envelope
     * @param policy - A verification policy to apply to the signing certificate
     * @returns The payload type and payload bytes from the verified envelope
     */
    verifyDsse(bundle: SigstoreBundle, policy: VerificationPolicy): Promise<{
        payloadType: string;
        payload: Uint8Array;
    }>;
}
