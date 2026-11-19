/*
 * A public key supplied by the caller for managed-key (non-certificate)
 * verification. It is the only key such verification uses: nothing in a
 * bundle, such as publicKey.hint, can select or replace it.
 */
import { ASN1Obj, EcdsaTypes, HashAlgorithms, importKey, KeyTypes, toDER, uint8ArrayEqual, Uint8ArrayToBase64, } from "@freedomofpress/crypto-browser";
import { fail } from "./errors.js";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_CURVE_P256 = "1.2.840.10045.3.1.7"; // prime256v1
const OID_CURVE_P384 = "1.3.132.0.34"; // secp384r1
const CURVES = {
    [OID_CURVE_P256]: {
        namedCurve: EcdsaTypes.P256,
        hash: HashAlgorithms.SHA256,
        keyDetails: "PKIX_ECDSA_P256_SHA_256",
        digestAlgorithm: "SHA2_256",
        digestLength: 32,
    },
    [OID_CURVE_P384]: {
        namedCurve: EcdsaTypes.P384,
        hash: HashAlgorithms.SHA384,
        keyDetails: "PKIX_ECDSA_P384_SHA_384",
        digestAlgorithm: "SHA2_384",
        digestLength: 48,
    },
};
// The key details a Rekor v2 entry may declare, with the curve and digest each one names.
const KEY_DETAILS = Object.fromEntries(Object.values(CURVES).map((c) => [c.keyDetails, c]));
// Returns the curve of an ECDSA SubjectPublicKeyInfo, or undefined for anything else.
function ecdsaCurve(spki) {
    try {
        const asn1 = ASN1Obj.parseBuffer(spki);
        const algorithm = asn1.subs[0];
        if (asn1.subs.length !== 2 || algorithm.subs.length !== 2) {
            return undefined;
        }
        if (algorithm.subs[0].toOID() !== OID_EC_PUBLIC_KEY) {
            return undefined;
        }
        const oid = algorithm.subs[1].toOID();
        if (!Object.prototype.hasOwnProperty.call(CURVES, oid)) {
            return undefined;
        }
        return CURVES[oid];
    }
    catch {
        return undefined;
    }
}
export class ManagedPublicKey {
    constructor(spki, curve) {
        this.spki = spki;
        // Snapshot the metadata: curveForKeyDetails exposes the shared table to callers.
        this.namedCurve = curve.namedCurve;
        this.hash = curve.hash;
        this.keyDetails = curve.keyDetails;
        this.digestAlgorithm = curve.digestAlgorithm;
        this.digestLength = curve.digestLength;
    }
    /**
     * Accepts a PEM "PUBLIC KEY" or DER SubjectPublicKeyInfo. Only ECDSA P-256 and
     * P-384 keys are supported; anything else throws a VerificationError with code
     * "key-unsupported".
     */
    static from(key) {
        let der;
        if (typeof key === "string") {
            if (!key.includes("-----BEGIN PUBLIC KEY-----")) {
                fail("key-unsupported", "Public key must be a PEM PUBLIC KEY or DER SubjectPublicKeyInfo");
            }
            try {
                der = toDER(key.trim());
            }
            catch {
                fail("key-unsupported", "Public key PEM is not valid base64");
            }
        }
        else {
            der = key.slice();
        }
        const curve = ecdsaCurve(der);
        if (!curve) {
            fail("key-unsupported", "Only ECDSA P-256 and P-384 public keys are supported");
        }
        return new ManagedPublicKey(der, curve);
    }
    /** Curve and digest named by Rekor key details, if they are ones this verifier understands. */
    static curveForKeyDetails(keyDetails) {
        if (typeof keyDetails !== "string") {
            return undefined;
        }
        if (!Object.prototype.hasOwnProperty.call(KEY_DETAILS, keyDetails)) {
            return undefined;
        }
        return KEY_DETAILS[keyDetails];
    }
    /** Curve of an encoded SubjectPublicKeyInfo, if it is an ECDSA key on a supported curve. */
    static curveOf(spki) {
        return ecdsaCurve(spki)?.namedCurve;
    }
    /** True if `spki` is byte-for-byte this key's SubjectPublicKeyInfo. */
    equals(spki) {
        return uint8ArrayEqual(this.spki, spki);
    }
    get publicKey() {
        this.cryptoKey ?? (this.cryptoKey = this.importPublicKey());
        return this.cryptoKey;
    }
    importPublicKey() {
        const encodedKey = Uint8ArrayToBase64(this.spki);
        return importKey(KeyTypes.Ecdsa, this.namedCurve, encodedKey).catch(() => {
            fail("key-unsupported", "Public key could not be imported");
        });
    }
}
//# sourceMappingURL=key.js.map