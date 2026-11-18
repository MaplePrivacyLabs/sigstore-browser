/*
 * A public key supplied by the caller for managed-key (non-certificate)
 * verification. It is the only key such verification uses: nothing in a
 * bundle, such as publicKey.hint, can select or replace it.
 */
import { ASN1Obj, EcdsaTypes, HashAlgorithms, importKey, KeyTypes, toDER, uint8ArrayEqual, Uint8ArrayToBase64, } from "@freedomofpress/crypto-browser";
import { fail } from "./errors.js";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const CURVES = {
    "1.2.840.10045.3.1.7": {
        namedCurve: EcdsaTypes.P256,
        hash: HashAlgorithms.SHA256,
        keyDetails: "PKIX_ECDSA_P256_SHA_256",
        digestAlgorithm: "SHA2_256",
        digestLength: 32,
    },
    "1.3.132.0.34": {
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
        if (asn1.subs.length !== 2 || algorithm.subs.length !== 2)
            return undefined;
        if (algorithm.subs[0].toOID() !== OID_EC_PUBLIC_KEY)
            return undefined;
        const oid = algorithm.subs[1].toOID();
        return Object.prototype.hasOwnProperty.call(CURVES, oid) ? CURVES[oid] : undefined;
    }
    catch {
        return undefined;
    }
}
export class ManagedPublicKey {
    constructor(spki, curve) {
        this.spki = spki;
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
    static keyDetails(keyDetails) {
        return typeof keyDetails === "string" && Object.prototype.hasOwnProperty.call(KEY_DETAILS, keyDetails) ? KEY_DETAILS[keyDetails] : undefined;
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
        this.cryptoKey ?? (this.cryptoKey = importKey(KeyTypes.Ecdsa, this.namedCurve, Uint8ArrayToBase64(this.spki)).catch(() => fail("key-unsupported", "Public key could not be imported")));
        return this.cryptoKey;
    }
}
//# sourceMappingURL=key.js.map