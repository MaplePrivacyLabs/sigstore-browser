type SigstoreBundleBase = {
    mediaType: string;
    verificationMaterial: VerificationMaterial;
};
export type SigstoreBundle = (SigstoreBundleBase & {
    messageSignature: MessageSignature;
    dsseEnvelope?: never;
}) | (SigstoreBundleBase & {
    messageSignature?: never;
    dsseEnvelope: DSSEEnvelope;
});
export interface VerificationMaterial {
    certificate?: Certificate;
    x509CertificateChain?: X509CertificateChain;
    publicKey?: PublicKeyIdentifier;
    tlogEntries: TLogEntry[];
    timestampVerificationData?: TimestampVerificationData;
}
export interface Certificate {
    rawBytes: string;
}
export interface PublicKeyIdentifier {
    hint?: string;
}
export interface X509CertificateChain {
    certificates: Certificate[];
}
export interface TLogEntry {
    logIndex: string;
    logId: LogId;
    kindVersion: KindVersion;
    integratedTime: string | null;
    inclusionPromise?: InclusionPromise;
    inclusionProof?: InclusionProof;
    canonicalizedBody: string;
}
export interface LogId {
    keyId: string;
}
export interface KindVersion {
    kind: string;
    version: string;
}
export interface InclusionPromise {
    signedEntryTimestamp: string;
}
export interface InclusionProof {
    logIndex: string;
    rootHash: string;
    treeSize: string;
    hashes: string[];
    checkpoint: Checkpoint;
}
export interface Checkpoint {
    envelope: string;
}
export interface MessageSignature {
    messageDigest: MessageDigest;
    signature: string;
}
export interface MessageDigest {
    algorithm: string;
    digest: string;
}
export interface DSSEEnvelope {
    payload: string;
    payloadType: string;
    signatures: DSSESignature[];
}
export interface DSSESignature {
    sig: string;
    keyid?: string;
}
export interface TimestampVerificationData {
    rfc3161Timestamps?: RFC3161Timestamp[];
}
export interface RFC3161Timestamp {
    signedTimestamp: string;
}
export interface InTotoStatement {
    _type: string;
    subject: InTotoSubject[];
    predicateType: string;
    predicate: Record<string, unknown>;
}
export interface InTotoSubject {
    name: string;
    digest: Record<string, string>;
}
export declare function assertTimestampVerificationData(data: unknown): asserts data is TimestampVerificationData | undefined;
export declare function assertBundle(b: unknown, material?: "certificate" | "publicKey"): asserts b is SigstoreBundle;
export {};
