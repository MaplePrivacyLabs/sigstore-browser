/*
 * TSA (Time-Stamping Authority) timestamp verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/tsa.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Uses Web Crypto API for all cryptographic operations
 * - Integrates with existing RFC3161 timestamp implementation
 * - Uses CertificateChainVerifier for full X.509 path validation
 * - Implements filterCertAuthorities inline (from sigstore-js/packages/verify/src/trust/filter.ts)
 * - Adds verifyBundleTimestamp for Sigstore bundle integration (new functionality)
 */
import { base64ToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { assertTimestampVerificationData } from "../bundle.js";
import { fail, VerificationError } from "../errors.js";
import { parseValidityPeriod } from "../interfaces.js";
import { RFC3161TimestampVerificationError } from "../rfc3161/error.js";
import { RFC3161Timestamp } from "../rfc3161/index.js";
import { CertificateChainVerifier, X509Certificate } from "../x509/index.js";
/**
 * Verifies an RFC3161 timestamp against a set of timestamp authorities
 *
 * @param timestamp - The RFC3161 timestamp to verify
 * @param data - The data that was timestamped
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time
 * @throws Error if timestamp cannot be verified
 */
export async function verifyRFC3161Timestamp(timestamp, data, timestampAuthorities) {
    return (await verifyTimestamp(timestamp, data, timestampAuthorities)).signingTime;
}
async function verifyTimestamp(timestamp, data, timestampAuthorities) {
    const signingTime = timestamp.signingTime;
    // Filter for CAs which were valid at the time of signing
    let validAuthorities = filterCertAuthorities(timestampAuthorities, signingTime);
    // Filter for CAs which match serial and issuer embedded in the timestamp
    validAuthorities = filterCAsBySerialAndIssuer(validAuthorities, {
        serialNumber: timestamp.signerSerialNumber,
        issuer: timestamp.signerIssuer,
    });
    // Check that we can verify the timestamp with AT LEAST ONE of the remaining CAs
    const verificationResults = await Promise.allSettled(validAuthorities.map(ca => verifyTimestampForCA(timestamp, data, ca)));
    const verified = verificationResults.findIndex(result => result.status === "fulfilled");
    if (verified < 0) {
        const errors = verificationResults
            .filter(r => r.status === "rejected")
            .map(r => r.reason?.message || 'Unknown error');
        throw new Error(`Timestamp could not be verified against any trusted authority. Errors: ${errors.join(', ')}`);
    }
    const ca = validAuthorities[verified];
    return { signingTime, operator: ca.operator || "" };
}
/**
 * Filters certificate authorities to those valid at a specific time
 *
 * Adapted from sigstore-js/packages/verify/src/trust/filter.ts
 */
function filterCertAuthorities(authorities, validAt) {
    return authorities.filter(ca => {
        const { start, end } = parseValidityPeriod(ca.validFor);
        return start <= validAt && validAt <= end;
    });
}
/**
 * Filters certificate authorities by serial number and issuer
 *
 * Only checks the LEAF certificate (TSA signing cert), not the entire chain.
 * This matches the sigstore-js reference implementation.
 */
function filterCAsBySerialAndIssuer(timestampAuthorities, criteria) {
    return timestampAuthorities.filter(ca => {
        if (!ca.certChain || ca.certChain.certificates.length === 0) {
            return false;
        }
        const leafCert = X509Certificate.parse(base64ToUint8Array(ca.certChain.certificates[0].rawBytes));
        return uint8ArrayEqual(leafCert.serialNumber, criteria.serialNumber) &&
            uint8ArrayEqual(leafCert.issuer, criteria.issuer);
    });
}
/**
 * Verifies a timestamp against a specific certificate authority
 */
async function verifyTimestampForCA(timestamp, data, ca) {
    if (!ca.certChain || ca.certChain.certificates.length === 0) {
        throw new Error("Certificate authority missing certificate chain");
    }
    const leafCert = X509Certificate.parse(base64ToUint8Array(ca.certChain.certificates[0].rawBytes));
    const signingTime = timestamp.signingTime;
    const trustedCerts = ca.certChain.certificates
        .slice(1)
        .map(cert => X509Certificate.parse(base64ToUint8Array(cert.rawBytes)));
    try {
        const verifier = new CertificateChainVerifier({
            untrustedCert: leafCert,
            trustedCerts: trustedCerts,
            timestamp: signingTime,
        });
        await verifier.verify();
    }
    catch (e) {
        throw new Error(`TSA certificate chain verification failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    const publicKey = await leafCert.publicKeyObj;
    await timestamp.verify(data, publicKey);
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
export async function verifyBundleTimestamp(timestampData, signature, timestampAuthorities) {
    assertTimestampVerificationData(timestampData);
    if (!timestampData?.rfc3161Timestamps?.length) {
        return [];
    }
    // Verify ALL timestamps - each must succeed (matches sigstore-js behavior)
    // Collect verification results for duplicate checking after verification
    // Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L86-L92
    const verifiedResults = [];
    for (const tsData of timestampData.rfc3161Timestamps) {
        // Decode the base64-encoded timestamp
        const timestampBytes = base64ToUint8Array(tsData.signedTimestamp);
        const timestamp = RFC3161Timestamp.parse(timestampBytes);
        verifiedResults.push({
            ...(await verifyTimestamp(timestamp, signature, timestampAuthorities)),
            signerSerialNumber: Array.from(timestamp.signerSerialNumber).join(','),
        });
    }
    // Check for duplicate timestamps using deep equality on parsed values
    // sigstore-js uses isDeepStrictEqual on {type, logID, timestamp} objects
    for (let i = 0; i < verifiedResults.length; i++) {
        for (let j = i + 1; j < verifiedResults.length; j++) {
            if (verifiedResults[i].signingTime.getTime() === verifiedResults[j].signingTime.getTime() &&
                verifiedResults[i].signerSerialNumber === verifiedResults[j].signerSerialNumber) {
                throw new Error("Duplicate TSA timestamp detected");
            }
        }
    }
    return verifiedResults;
}
/**
 * Verifies every RFC 3161 timestamp in a bundle over `signature`, like verifyBundleTimestamp, but
 * reports why one fails with a VerificationError code: "timestamp-malformed",
 * "timestamp-untrusted-authority" (no trusted authority, valid at the timestamp's time, issued it),
 * "timestamp-message-mismatch" (it covers another signature), "timestamp-signature-invalid" or
 * "timestamp-duplicate". Only certificates from the trusted root are used, never ones in the token.
 */
export async function verifyBundleTimestampForSignature(timestampData, signature, timestampAuthorities) {
    assertTimestampVerificationData(timestampData);
    const verified = [];
    for (const tsData of timestampData?.rfc3161Timestamps ?? []) {
        let timestamp;
        let signerSerialNumber;
        let signerIssuer;
        let signingTime;
        try {
            timestamp = RFC3161Timestamp.parse(base64ToUint8Array(tsData.signedTimestamp));
            signerSerialNumber = timestamp.signerSerialNumber;
            signerIssuer = timestamp.signerIssuer;
            signingTime = timestamp.signingTime;
        }
        catch (e) {
            fail("timestamp-malformed", `Malformed RFC 3161 timestamp: ${e instanceof Error ? e.message : String(e)}`);
        }
        const candidates = filterCAsBySerialAndIssuer(filterCertAuthorities(timestampAuthorities, signingTime), { serialNumber: signerSerialNumber, issuer: signerIssuer });
        // The failure from an authority whose chain verified says more than an untrusted chain.
        let failure;
        let authority;
        for (const ca of candidates) {
            let publicKey;
            try {
                publicKey = await verifiedAuthorityKey(ca, signingTime);
            }
            catch (e) {
                failure ?? (failure = new VerificationError("timestamp-untrusted-authority", e instanceof Error ? e.message : String(e)));
                continue;
            }
            try {
                await timestamp.verify(signature, publicKey);
                authority = ca;
                break;
            }
            catch (e) {
                failure = e instanceof RFC3161TimestampVerificationError
                    ? new VerificationError(e.code, `RFC 3161 timestamp: ${e.message}`)
                    : new VerificationError("timestamp-malformed", `RFC 3161 timestamp: ${e instanceof Error ? e.message : String(e)}`);
            }
        }
        if (!authority) {
            throw failure ?? new VerificationError("timestamp-untrusted-authority", "RFC 3161 timestamp was not issued by a timestamp authority in the trusted root");
        }
        const serial = Array.from(signerSerialNumber).join(",");
        if (verified.some((v) => v.signingTime.getTime() === signingTime.getTime() && v.signerSerialNumber === serial)) {
            fail("timestamp-duplicate", "Duplicate TSA timestamp detected");
        }
        verified.push({ signingTime, operator: authority.operator || "", signerSerialNumber: serial });
    }
    return verified.map(({ signingTime, operator }) => ({ signingTime, operator }));
}
// The authority's signing key, once its certificate chain from the trusted root verifies at `signingTime`.
async function verifiedAuthorityKey(ca, signingTime) {
    const [leaf, ...rest] = ca.certChain.certificates.map((cert) => X509Certificate.parse(base64ToUint8Array(cert.rawBytes)));
    try {
        await new CertificateChainVerifier({ untrustedCert: leaf, trustedCerts: rest, timestamp: signingTime }).verify();
    }
    catch (e) {
        throw new Error(`TSA certificate chain verification failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    return leaf.publicKeyObj;
}
//# sourceMappingURL=tsa.js.map