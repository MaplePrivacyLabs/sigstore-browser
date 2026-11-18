export interface CurveInfo {
    namedCurve: string;
    hash: string;
    keyDetails: string;
    digestAlgorithm: string;
    digestLength: number;
}
export declare class ManagedPublicKey {
    readonly spki: Uint8Array;
    readonly namedCurve: string;
    readonly hash: string;
    readonly keyDetails: string;
    readonly digestAlgorithm: string;
    readonly digestLength: number;
    private cryptoKey;
    private constructor();
    /**
     * Accepts a PEM "PUBLIC KEY" or DER SubjectPublicKeyInfo. Only ECDSA P-256 and
     * P-384 keys are supported; anything else throws a VerificationError with code
     * "key-unsupported".
     */
    static from(key: string | Uint8Array): ManagedPublicKey;
    /** Curve and digest named by Rekor key details, if they are ones this verifier understands. */
    static keyDetails(keyDetails: unknown): CurveInfo | undefined;
    /** Curve of an encoded SubjectPublicKeyInfo, if it is an ECDSA key on a supported curve. */
    static curveOf(spki: Uint8Array): string | undefined;
    /** True if `spki` is byte-for-byte this key's SubjectPublicKeyInfo. */
    equals(spki: Uint8Array): boolean;
    get publicKey(): Promise<CryptoKey>;
}
