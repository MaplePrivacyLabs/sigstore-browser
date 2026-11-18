import { RawTimestampAuthority } from "../interfaces.js";
import { RFC3161Timestamp } from "../rfc3161/index.js";
/**
 * Verifies an RFC3161 timestamp against a set of timestamp authorities
 *
 * @param timestamp - The RFC3161 timestamp to verify
 * @param data - The data that was timestamped
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time
 * @throws Error if timestamp cannot be verified
 */
export declare function verifyRFC3161Timestamp(timestamp: RFC3161Timestamp, data: Uint8Array, timestampAuthorities: RawTimestampAuthority[]): Promise<Date>;
export interface VerifiedTimestamp {
    signingTime: Date;
    operator: string;
}
/**
 * Verifies all timestamps in a bundle's timestamp verification data
 *
 * Matches sigstore-js behavior: all timestamps must successfully verify.
 * Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L64-L108
 *
 * @param timestampData - The timestamp verification data from the bundle
 * @param signature - The signature being verified
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing times and their operators (empty if no timestamps present)
 * @throws Error if any timestamp fails verification or duplicates are found
 */
export declare function verifyBundleTimestamp(timestampData: unknown, signature: Uint8Array, timestampAuthorities: RawTimestampAuthority[]): Promise<VerifiedTimestamp[]>;
/**
 * Verifies every RFC 3161 timestamp in a bundle over `signature`, like verifyBundleTimestamp, but
 * reports why one fails with a VerificationError code: "timestamp-malformed",
 * "timestamp-untrusted-authority" (no trusted authority, valid at the timestamp's time, issued it),
 * "timestamp-message-mismatch" (it covers another signature), "timestamp-signature-invalid" or
 * "timestamp-duplicate". Only certificates from the trusted root are used, never ones in the token.
 */
export declare function verifyBundleTimestampForSignature(timestampData: unknown, signature: Uint8Array, timestampAuthorities: RawTimestampAuthority[]): Promise<VerifiedTimestamp[]>;
