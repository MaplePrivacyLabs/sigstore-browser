import { base64ToUint8Array, canonicalizeJCS, stringToUint8Array, Uint8ArrayToHex, verifySignature } from "@freedomofpress/crypto-browser";
// Verifies an entry's signed entry timestamp (inclusion promise) and returns the integrated time it binds.
export async function verifyInclusionPromise(entry, promise, log) {
    const integratedTime = Number(entry.integratedTime);
    const integratedDate = new Date(integratedTime * 1000);
    if (integratedDate < log.validFor.start || integratedDate > log.validFor.end) {
        throw new Error("Rekor key was not valid at the integrated time.");
    }
    const signed = stringToUint8Array(canonicalizeJCS({
        body: entry.canonicalizedBody,
        integratedTime,
        logIndex: Number(entry.logIndex),
        logID: Uint8ArrayToHex(log.logId),
    }));
    if (!(await verifySignature(log.publicKey, signed, base64ToUint8Array(promise), log.hashAlgorithm))) {
        throw new Error("Failed to verify the inclusion promise in the provided bundle.");
    }
    return integratedDate;
}
//# sourceMappingURL=set.js.map