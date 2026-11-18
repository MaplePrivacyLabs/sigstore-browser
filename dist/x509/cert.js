/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { ASN1Obj, importKey, toDER, uint8ArrayEqual, Uint8ArrayToBase64, Uint8ArrayToString, verifySignature } from "@freedomofpress/crypto-browser";
import { KeyTypes } from "../interfaces.js";
import { DEFAULT_HASH_ALGORITHM, ECDSA_CURVE_NAMES, ECDSA_SIGNATURE_ALGOS, OID_RSASSA_PSS, RSA_SIGNATURE_ALGOS, SHA2_HASH_ALGOS } from "../oid.js";
import { X509AuthorityKeyIDExtension, X509BasicConstraintsExtension, X509BuildConfigDigestExtension, X509BuildConfigURIExtension, X509BuildSignerDigestExtension, X509BuildSignerURIExtension, X509BuildTriggerExtension, X509Extension, X509FulcioIssuerV1, X509FulcioIssuerV2, X509GitHubWorkflowNameExtension, X509GitHubWorkflowRefExtension, X509GitHubWorkflowRepositoryExtension, X509GitHubWorkflowSHAExtension, X509GitHubWorkflowTriggerExtension, X509KeyUsageExtension, X509RunInvocationURIExtension, X509RunnerEnvironmentExtension, X509SCTExtension, X509SourceRepositoryDigestExtension, X509SourceRepositoryIdentifierExtension, X509SourceRepositoryOwnerIdentifierExtension, X509SourceRepositoryOwnerURIExtension, X509SourceRepositoryRefExtension, X509SourceRepositoryURIExtension, X509SourceRepositoryVisibilityExtension, X509SubjectAlternativeNameExtension, X509SubjectKeyIDExtension, } from "./ext.js";
// Standard X.509 extension OIDs
const EXTENSION_OID_SUBJECT_KEY_ID = "2.5.29.14";
const EXTENSION_OID_KEY_USAGE = "2.5.29.15";
const EXTENSION_OID_SUBJECT_ALT_NAME = "2.5.29.17";
const EXTENSION_OID_BASIC_CONSTRAINTS = "2.5.29.19";
const EXTENSION_OID_AUTHORITY_KEY_ID = "2.5.29.35";
// CT Log SCT extension OID
export const EXTENSION_OID_SCT = "1.3.6.1.4.1.11129.2.4.2";
// Distinguished Name attribute OIDs (X.500)
const DN_OID_COMMON_NAME = "2.5.4.3";
const DN_OID_COUNTRY = "2.5.4.6";
const DN_OID_LOCALITY = "2.5.4.7";
const DN_OID_STATE = "2.5.4.8";
const DN_OID_ORGANIZATION = "2.5.4.10";
const DN_OID_ORGANIZATIONAL_UNIT = "2.5.4.11";
const DN_OID_TO_NAME = {
    [DN_OID_COMMON_NAME]: "CN",
    [DN_OID_COUNTRY]: "C",
    [DN_OID_LOCALITY]: "L",
    [DN_OID_STATE]: "ST",
    [DN_OID_ORGANIZATION]: "O",
    [DN_OID_ORGANIZATIONAL_UNIT]: "OU",
};
// Fulcio extension OIDs
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
export const EXTENSION_OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
export const EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER = "1.3.6.1.4.1.57264.1.2";
export const EXTENSION_OID_GITHUB_WORKFLOW_SHA = "1.3.6.1.4.1.57264.1.3";
export const EXTENSION_OID_GITHUB_WORKFLOW_NAME = "1.3.6.1.4.1.57264.1.4";
export const EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY = "1.3.6.1.4.1.57264.1.5";
export const EXTENSION_OID_GITHUB_WORKFLOW_REF = "1.3.6.1.4.1.57264.1.6";
export const EXTENSION_OID_OTHERNAME = "1.3.6.1.4.1.57264.1.7";
export const EXTENSION_OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
export const EXTENSION_OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9";
export const EXTENSION_OID_BUILD_SIGNER_DIGEST = "1.3.6.1.4.1.57264.1.10";
export const EXTENSION_OID_RUNNER_ENVIRONMENT = "1.3.6.1.4.1.57264.1.11";
export const EXTENSION_OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12";
export const EXTENSION_OID_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13";
export const EXTENSION_OID_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14";
export const EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15";
export const EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI = "1.3.6.1.4.1.57264.1.16";
export const EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17";
export const EXTENSION_OID_BUILD_CONFIG_URI = "1.3.6.1.4.1.57264.1.18";
export const EXTENSION_OID_BUILD_CONFIG_DIGEST = "1.3.6.1.4.1.57264.1.19";
export const EXTENSION_OID_BUILD_TRIGGER = "1.3.6.1.4.1.57264.1.20";
export const EXTENSION_OID_RUN_INVOCATION_URI = "1.3.6.1.4.1.57264.1.21";
export const EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY = "1.3.6.1.4.1.57264.1.22";
export class X509Certificate {
    constructor(asn1) {
        this.root = asn1;
    }
    static parse(cert) {
        const der = typeof cert === "string" ? toDER(cert) : cert;
        const asn1 = ASN1Obj.parseBuffer(der);
        return new X509Certificate(asn1);
    }
    get tbsCertificate() {
        return this.tbsCertificateObj;
    }
    get version() {
        // version number is the first element of the version context specific tag
        const ver = this.versionObj.subs[0].toInteger();
        return `v${(ver + BigInt(1)).toString()}`;
    }
    get serialNumber() {
        return this.serialNumberObj.value;
    }
    get notBefore() {
        // notBefore is the first element of the validity sequence
        return this.validityObj.subs[0].toDate();
    }
    get notAfter() {
        // notAfter is the second element of the validity sequence
        return this.validityObj.subs[1].toDate();
    }
    get issuer() {
        return this.issuerObj.value;
    }
    get subject() {
        return this.subjectObj.value;
    }
    /**
     * Returns the issuer distinguished name as a Map of attribute names to values.
     * Common attributes: CN (Common Name), O (Organization), L (Locality),
     * ST (State), C (Country), OU (Organizational Unit)
     */
    get issuerDN() {
        return this.parseDistinguishedName(this.issuerObj);
    }
    /**
     * Returns the subject distinguished name as a Map of attribute names to values.
     * Common attributes: CN (Common Name), O (Organization), L (Locality),
     * ST (State), C (Country), OU (Organizational Unit)
     */
    get subjectDN() {
        return this.parseDistinguishedName(this.subjectObj);
    }
    get publicKey() {
        return this.subjectPublicKeyInfoObj.toDER();
    }
    /**
     * Import the public key with a specific hash algorithm and signature scheme for RSA keys.
     * For ECDSA keys, both parameters are ignored.
     * @param hashAlg - Hash algorithm (e.g., "sha384") for RSA keys
     * @param usePss - If true, import as RSA-PSS key; if false, import as PKCS#1 v1.5
     */
    async getPublicKeyObj(hashAlg, usePss) {
        const publicKey = this.subjectPublicKeyInfoObj.toDER();
        const spki = ASN1Obj.parseBuffer(publicKey);
        const algorithmOID = spki.subs[0].subs[0].toOID();
        // RSA key (OID 1.2.840.113549.1.1.1) or RSA-PSS key (OID 1.2.840.113549.1.1.10)
        const isRsaKey = algorithmOID === "1.2.840.113549.1.1.1";
        const isRsaPssKey = algorithmOID === OID_RSASSA_PSS;
        if (isRsaPssKey) {
            // WebCrypto doesn't support importing keys with id-RSASSA-PSS OID, only rsaEncryption
            throw new Error("RSA-PSS public keys (id-RSASSA-PSS OID) are not supported by WebCrypto. " +
                "Only certificates with standard RSA keys (rsaEncryption OID) signed using RSA-PSS are supported.");
        }
        if (isRsaKey) {
            const hash = hashAlg || DEFAULT_HASH_ALGORITHM;
            // crypto-browser extracts hash from scheme and uses PSS unless "PKCS1" is present
            const scheme = usePss ? hash : `PKCS1_${hash}`;
            return importKey(KeyTypes.RSA, scheme, Uint8ArrayToBase64(publicKey));
        }
        else {
            // ECDSA key - the curve OID is in the second element
            const curveOID = spki.subs[0].subs[1]?.toOID();
            const curve = ECDSA_CURVE_NAMES[curveOID];
            if (!curve) {
                throw new Error(`Unknown ECDSA curve OID: ${curveOID}`);
            }
            return importKey(KeyTypes.Ecdsa, curve, Uint8ArrayToBase64(publicKey));
        }
    }
    get publicKeyObj() {
        return this.getPublicKeyObj();
    }
    get signatureAlgorithm() {
        const oid = this.signatureAlgorithmObj.subs[0].toOID();
        return ECDSA_SIGNATURE_ALGOS[oid] || RSA_SIGNATURE_ALGOS[oid] || this.parseRsaPssHashAlgorithm();
    }
    get signatureAlgorithmOid() {
        return this.signatureAlgorithmObj.subs[0].toOID();
    }
    /**
     * Parse hash algorithm from RSA-PSS signature algorithm parameters.
     * RSA-PSS parameters are: SEQUENCE { hashAlgorithm, maskGenAlgorithm, saltLength, trailerField }
     */
    parseRsaPssHashAlgorithm() {
        const sigAlgOid = this.signatureAlgorithmObj.subs[0].toOID();
        if (sigAlgOid !== OID_RSASSA_PSS) {
            return "";
        }
        // RSA-PSS has parameters in the second element of the signature algorithm sequence
        const params = this.signatureAlgorithmObj.subs[1];
        if (!params || params.subs.length === 0) {
            return DEFAULT_HASH_ALGORITHM;
        }
        // First element is hashAlgorithm [0] EXPLICIT
        const hashAlgWrapper = params.subs[0];
        if (hashAlgWrapper && hashAlgWrapper.subs.length > 0) {
            // The wrapper contains a SEQUENCE with the hash algorithm OID
            const hashAlgSeq = hashAlgWrapper.subs[0];
            if (hashAlgSeq && hashAlgSeq.subs.length > 0) {
                const hashOid = hashAlgSeq.subs[0].toOID();
                return SHA2_HASH_ALGOS[hashOid] || DEFAULT_HASH_ALGORITHM;
            }
        }
        return DEFAULT_HASH_ALGORITHM;
    }
    get signatureValue() {
        // Signature value is a bit string, so we need to skip the first byte
        return this.signatureValueObj.value.subarray(1);
    }
    get subjectAltName() {
        const ext = this.extSubjectAltName;
        return ext?.uri || ext?.rfc822Name;
    }
    get extensions() {
        // The extension list is the first (and only) element of the extensions
        // context specific tag
        const extSeq = this.extensionsObj?.subs[0];
        return extSeq?.subs || /* istanbul ignore next */ [];
    }
    get extKeyUsage() {
        const ext = this.findExtension(EXTENSION_OID_KEY_USAGE);
        return ext ? new X509KeyUsageExtension(ext) : undefined;
    }
    get extBasicConstraints() {
        const ext = this.findExtension(EXTENSION_OID_BASIC_CONSTRAINTS);
        return ext ? new X509BasicConstraintsExtension(ext) : undefined;
    }
    get extSubjectAltName() {
        const ext = this.findExtension(EXTENSION_OID_SUBJECT_ALT_NAME);
        return ext ? new X509SubjectAlternativeNameExtension(ext) : undefined;
    }
    get extAuthorityKeyID() {
        const ext = this.findExtension(EXTENSION_OID_AUTHORITY_KEY_ID);
        return ext ? new X509AuthorityKeyIDExtension(ext) : undefined;
    }
    get extSubjectKeyID() {
        const ext = this.findExtension(EXTENSION_OID_SUBJECT_KEY_ID);
        return ext
            ? new X509SubjectKeyIDExtension(ext)
            : /* istanbul ignore next */ undefined;
    }
    get extSCT() {
        const ext = this.findExtension(EXTENSION_OID_SCT);
        return ext ? new X509SCTExtension(ext) : undefined;
    }
    get extFulcioIssuerV1() {
        const ext = this.findExtension(EXTENSION_OID_FULCIO_ISSUER_V1);
        return ext ? new X509FulcioIssuerV1(ext) : undefined;
    }
    get extFulcioIssuerV2() {
        const ext = this.findExtension(EXTENSION_OID_FULCIO_ISSUER_V2);
        return ext ? new X509FulcioIssuerV2(ext) : undefined;
    }
    get extGitHubWorkflowTrigger() {
        const ext = this.findExtension(EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER);
        return ext ? new X509GitHubWorkflowTriggerExtension(ext) : undefined;
    }
    get extGitHubWorkflowSHA() {
        const ext = this.findExtension(EXTENSION_OID_GITHUB_WORKFLOW_SHA);
        return ext ? new X509GitHubWorkflowSHAExtension(ext) : undefined;
    }
    get extGitHubWorkflowName() {
        const ext = this.findExtension(EXTENSION_OID_GITHUB_WORKFLOW_NAME);
        return ext ? new X509GitHubWorkflowNameExtension(ext) : undefined;
    }
    get extGitHubWorkflowRepository() {
        const ext = this.findExtension(EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY);
        return ext ? new X509GitHubWorkflowRepositoryExtension(ext) : undefined;
    }
    get extGitHubWorkflowRef() {
        const ext = this.findExtension(EXTENSION_OID_GITHUB_WORKFLOW_REF);
        return ext ? new X509GitHubWorkflowRefExtension(ext) : undefined;
    }
    get extBuildSignerURI() {
        const ext = this.findExtension(EXTENSION_OID_BUILD_SIGNER_URI);
        return ext ? new X509BuildSignerURIExtension(ext) : undefined;
    }
    get extBuildSignerDigest() {
        const ext = this.findExtension(EXTENSION_OID_BUILD_SIGNER_DIGEST);
        return ext ? new X509BuildSignerDigestExtension(ext) : undefined;
    }
    get extRunnerEnvironment() {
        const ext = this.findExtension(EXTENSION_OID_RUNNER_ENVIRONMENT);
        return ext ? new X509RunnerEnvironmentExtension(ext) : undefined;
    }
    get extSourceRepositoryURI() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_URI);
        return ext ? new X509SourceRepositoryURIExtension(ext) : undefined;
    }
    get extSourceRepositoryDigest() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_DIGEST);
        return ext ? new X509SourceRepositoryDigestExtension(ext) : undefined;
    }
    get extSourceRepositoryRef() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_REF);
        return ext ? new X509SourceRepositoryRefExtension(ext) : undefined;
    }
    get extSourceRepositoryIdentifier() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER);
        return ext ? new X509SourceRepositoryIdentifierExtension(ext) : undefined;
    }
    get extSourceRepositoryOwnerURI() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI);
        return ext ? new X509SourceRepositoryOwnerURIExtension(ext) : undefined;
    }
    get extSourceRepositoryOwnerIdentifier() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER);
        return ext ? new X509SourceRepositoryOwnerIdentifierExtension(ext) : undefined;
    }
    get extBuildConfigURI() {
        const ext = this.findExtension(EXTENSION_OID_BUILD_CONFIG_URI);
        return ext ? new X509BuildConfigURIExtension(ext) : undefined;
    }
    get extBuildConfigDigest() {
        const ext = this.findExtension(EXTENSION_OID_BUILD_CONFIG_DIGEST);
        return ext ? new X509BuildConfigDigestExtension(ext) : undefined;
    }
    get extBuildTrigger() {
        const ext = this.findExtension(EXTENSION_OID_BUILD_TRIGGER);
        return ext ? new X509BuildTriggerExtension(ext) : undefined;
    }
    get extRunInvocationURI() {
        const ext = this.findExtension(EXTENSION_OID_RUN_INVOCATION_URI);
        return ext ? new X509RunInvocationURIExtension(ext) : undefined;
    }
    get extSourceRepositoryVisibility() {
        const ext = this.findExtension(EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY);
        return ext ? new X509SourceRepositoryVisibilityExtension(ext) : undefined;
    }
    get isCA() {
        const ca = this.extBasicConstraints?.isCA || false;
        // If the KeyUsage extension is present, keyCertSign must be set
        if (this.extKeyUsage) {
            return ca && this.extKeyUsage.keyCertSign;
        }
        return ca;
    }
    extension(oid) {
        const ext = this.findExtension(oid);
        return ext ? new X509Extension(ext) : undefined;
    }
    async verify(issuerCertificate) {
        // Extract the hash algorithm from this certificate's signature algorithm
        const sigAlgOID = this.signatureAlgorithmOid;
        const isRsaPss = sigAlgOID === OID_RSASSA_PSS;
        // Get hash algorithm - for RSA-PSS, parse from parameters; otherwise lookup in tables
        const hashAlg = isRsaPss
            ? this.parseRsaPssHashAlgorithm()
            : (RSA_SIGNATURE_ALGOS[sigAlgOID] || ECDSA_SIGNATURE_ALGOS[sigAlgOID]);
        // Use the issuer's public key if provided, otherwise use the subject's (for self-signed certs)
        // Import with the correct hash algorithm and key type for this certificate's signature
        const publicKeyObj = issuerCertificate
            ? await issuerCertificate.getPublicKeyObj(hashAlg, isRsaPss)
            : await this.getPublicKeyObj(hashAlg, isRsaPss);
        return await verifySignature(publicKeyObj, this.tbsCertificate.toDER(), this.signatureValue, this.signatureAlgorithm);
    }
    validForDate(date) {
        return this.notBefore <= date && date <= this.notAfter;
    }
    equals(other) {
        return uint8ArrayEqual(this.root.toDER(), other.root.toDER());
    }
    // Creates a copy of the certificate with a new buffer
    clone() {
        const der = this.root.toDER();
        const clone = new Uint8Array(der);
        return X509Certificate.parse(clone);
    }
    findExtension(oid) {
        // Find the extension with the given OID. The OID will always be the first
        // element of the extension sequence
        return this.extensions.find((ext) => ext.subs[0].toOID() === oid);
    }
    /////////////////////////////////////////////////////////////////////////////
    // The following properties use the documented x509 structure to locate the
    // desired ASN.1 object
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.1
    get tbsCertificateObj() {
        // tbsCertificate is the first element of the certificate sequence
        return this.root.subs[0];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
    get signatureAlgorithmObj() {
        // signatureAlgorithm is the second element of the certificate sequence
        return this.root.subs[1];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.3
    get signatureValueObj() {
        // signatureValue is the third element of the certificate sequence
        return this.root.subs[2];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.1
    get versionObj() {
        // version is the first element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[0];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
    get serialNumberObj() {
        // serialNumber is the second element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[1];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
    get issuerObj() {
        // issuer is the fourth element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[3];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    get validityObj() {
        // version is the fifth element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[4];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.6
    get subjectObj() {
        // subject is the sixth element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[5];
    }
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
    get subjectPublicKeyInfoObj() {
        // subjectPublicKeyInfo is the seventh element of the tbsCertificate sequence
        return this.tbsCertificateObj.subs[6];
    }
    // Extensions can't be located by index because their position varies. Instead,
    // we need to find the extensions context specific tag
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.9
    get extensionsObj() {
        return this.tbsCertificateObj.subs.find((sub) => sub.tag.isContextSpecific(0x03));
    }
    // Parse a Distinguished Name (issuer or subject) ASN1Obj into a Map
    // DN structure: SEQUENCE of SET of SEQUENCE (AttributeTypeAndValue)
    // Each AttributeTypeAndValue is [OID, value]
    parseDistinguishedName(dnObj) {
        const result = new Map();
        // Iterate over RDNs (RelativeDistinguishedName - each is a SET)
        for (const rdn of dnObj.subs) {
            // Each RDN contains one or more AttributeTypeAndValue (SEQUENCE)
            for (const atv of rdn.subs) {
                if (atv.subs.length >= 2) {
                    const oidObj = atv.subs[0];
                    const valueObj = atv.subs[1];
                    if (oidObj.tag.isOID()) {
                        const oid = oidObj.toOID();
                        const attrName = DN_OID_TO_NAME[oid];
                        if (attrName) {
                            const value = Uint8ArrayToString(valueObj.value);
                            result.set(attrName, value);
                        }
                    }
                }
            }
        }
        return result;
    }
}
//# sourceMappingURL=cert.js.map