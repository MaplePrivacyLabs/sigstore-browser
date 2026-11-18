/**
 * Base class for all verification errors
 * Provides structured error handling with error codes
 */
export declare class VerificationError extends Error {
    code: string;
    constructor(code: string, message: string);
}
/**
 * Error thrown when timestamp verification fails
 */
export declare class TimestampError extends VerificationError {
    constructor(message: string);
}
/**
 * Error thrown when certificate verification fails
 */
export declare class CertificateError extends VerificationError {
    constructor(message: string);
}
/**
 * Error thrown when transparency log verification fails
 */
export declare class TLogError extends VerificationError {
    constructor(message: string);
}
/**
 * Error thrown when signature verification fails
 */
export declare class SignatureError extends VerificationError {
    constructor(message: string);
}
/**
 * Error thrown when policy verification fails
 */
export declare class PolicyError extends VerificationError {
    constructor(message: string);
}
/**
 * Language-neutral reasons a managed-key verification fails, carried in
 * VerificationError.code. They name the first check that failed. The shared
 * managed-key test corpus records the same codes for its vectors.
 */
export declare const REASON_CODES: readonly ["bundle-too-large", "bundle-malformed", "duplicate-json-key", "conflicting-oneof", "media-type-unsupported", "verification-material-unsupported", "content-unsupported", "tlog-entry-count", "tlog-entry-kind", "tlog-entry-malformed", "tlog-unknown-log", "tlog-log-key-unsupported", "tlog-threshold", "integrated-time-present", "inclusion-promise-present", "inclusion-promise-missing", "inclusion-promise-invalid", "inclusion-proof-missing", "inclusion-proof-invalid", "checkpoint-malformed", "checkpoint-origin-mismatch", "checkpoint-signature-invalid", "tlog-key-details-mismatch", "tlog-digest-algorithm-mismatch", "tlog-digest-malformed", "tlog-digest-mismatch", "tlog-key-mismatch", "tlog-signature-mismatch", "key-unsupported", "dsse-signature-invalid", "message-signature-invalid", "payload-type-unsupported", "artifact-mismatch", "timestamp-count", "timestamp-duplicate", "timestamp-malformed", "timestamp-untrusted-authority", "timestamp-message-mismatch", "timestamp-signature-invalid", "timestamp-threshold"];
export type ReasonCode = (typeof REASON_CODES)[number];
/** Throws a VerificationError whose code is one of REASON_CODES. */
export declare function fail(code: ReasonCode, message: string): never;
