import { ASN1Obj } from "@freedomofpress/crypto-browser";
import { X509AuthorityKeyIDExtension, X509BasicConstraintsExtension, X509BuildConfigDigestExtension, X509BuildConfigURIExtension, X509BuildSignerDigestExtension, X509BuildSignerURIExtension, X509BuildTriggerExtension, X509Extension, X509FulcioIssuerV1, X509FulcioIssuerV2, X509GitHubWorkflowNameExtension, X509GitHubWorkflowRefExtension, X509GitHubWorkflowRepositoryExtension, X509GitHubWorkflowSHAExtension, X509GitHubWorkflowTriggerExtension, X509KeyUsageExtension, X509RunInvocationURIExtension, X509RunnerEnvironmentExtension, X509SCTExtension, X509SourceRepositoryDigestExtension, X509SourceRepositoryIdentifierExtension, X509SourceRepositoryOwnerIdentifierExtension, X509SourceRepositoryOwnerURIExtension, X509SourceRepositoryRefExtension, X509SourceRepositoryURIExtension, X509SourceRepositoryVisibilityExtension, X509SubjectAlternativeNameExtension, X509SubjectKeyIDExtension } from "./ext.js";
export declare const EXTENSION_OID_SCT = "1.3.6.1.4.1.11129.2.4.2";
export declare const EXTENSION_OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
export declare const EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER = "1.3.6.1.4.1.57264.1.2";
export declare const EXTENSION_OID_GITHUB_WORKFLOW_SHA = "1.3.6.1.4.1.57264.1.3";
export declare const EXTENSION_OID_GITHUB_WORKFLOW_NAME = "1.3.6.1.4.1.57264.1.4";
export declare const EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY = "1.3.6.1.4.1.57264.1.5";
export declare const EXTENSION_OID_GITHUB_WORKFLOW_REF = "1.3.6.1.4.1.57264.1.6";
export declare const EXTENSION_OID_OTHERNAME = "1.3.6.1.4.1.57264.1.7";
export declare const EXTENSION_OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
export declare const EXTENSION_OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9";
export declare const EXTENSION_OID_BUILD_SIGNER_DIGEST = "1.3.6.1.4.1.57264.1.10";
export declare const EXTENSION_OID_RUNNER_ENVIRONMENT = "1.3.6.1.4.1.57264.1.11";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI = "1.3.6.1.4.1.57264.1.16";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17";
export declare const EXTENSION_OID_BUILD_CONFIG_URI = "1.3.6.1.4.1.57264.1.18";
export declare const EXTENSION_OID_BUILD_CONFIG_DIGEST = "1.3.6.1.4.1.57264.1.19";
export declare const EXTENSION_OID_BUILD_TRIGGER = "1.3.6.1.4.1.57264.1.20";
export declare const EXTENSION_OID_RUN_INVOCATION_URI = "1.3.6.1.4.1.57264.1.21";
export declare const EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY = "1.3.6.1.4.1.57264.1.22";
export declare class X509Certificate {
    root: ASN1Obj;
    constructor(asn1: ASN1Obj);
    static parse(cert: Uint8Array | string): X509Certificate;
    get tbsCertificate(): ASN1Obj;
    get version(): string;
    get serialNumber(): Uint8Array;
    get notBefore(): Date;
    get notAfter(): Date;
    get issuer(): Uint8Array;
    get subject(): Uint8Array;
    /**
     * Returns the issuer distinguished name as a Map of attribute names to values.
     * Common attributes: CN (Common Name), O (Organization), L (Locality),
     * ST (State), C (Country), OU (Organizational Unit)
     */
    get issuerDN(): Map<string, string>;
    /**
     * Returns the subject distinguished name as a Map of attribute names to values.
     * Common attributes: CN (Common Name), O (Organization), L (Locality),
     * ST (State), C (Country), OU (Organizational Unit)
     */
    get subjectDN(): Map<string, string>;
    get publicKey(): Uint8Array;
    /**
     * Import the public key with a specific hash algorithm and signature scheme for RSA keys.
     * For ECDSA keys, both parameters are ignored.
     * @param hashAlg - Hash algorithm (e.g., "sha384") for RSA keys
     * @param usePss - If true, import as RSA-PSS key; if false, import as PKCS#1 v1.5
     */
    getPublicKeyObj(hashAlg?: string, usePss?: boolean): Promise<CryptoKey>;
    get publicKeyObj(): Promise<CryptoKey>;
    get signatureAlgorithm(): string;
    get signatureAlgorithmOid(): string;
    /**
     * Parse hash algorithm from RSA-PSS signature algorithm parameters.
     * RSA-PSS parameters are: SEQUENCE { hashAlgorithm, maskGenAlgorithm, saltLength, trailerField }
     */
    private parseRsaPssHashAlgorithm;
    get signatureValue(): Uint8Array;
    get subjectAltName(): string | undefined;
    get extensions(): ASN1Obj[];
    get extKeyUsage(): X509KeyUsageExtension | undefined;
    get extBasicConstraints(): X509BasicConstraintsExtension | undefined;
    get extSubjectAltName(): X509SubjectAlternativeNameExtension | undefined;
    get extAuthorityKeyID(): X509AuthorityKeyIDExtension | undefined;
    get extSubjectKeyID(): X509SubjectKeyIDExtension | undefined;
    get extSCT(): X509SCTExtension | undefined;
    get extFulcioIssuerV1(): X509FulcioIssuerV1 | undefined;
    get extFulcioIssuerV2(): X509FulcioIssuerV2 | undefined;
    get extGitHubWorkflowTrigger(): X509GitHubWorkflowTriggerExtension | undefined;
    get extGitHubWorkflowSHA(): X509GitHubWorkflowSHAExtension | undefined;
    get extGitHubWorkflowName(): X509GitHubWorkflowNameExtension | undefined;
    get extGitHubWorkflowRepository(): X509GitHubWorkflowRepositoryExtension | undefined;
    get extGitHubWorkflowRef(): X509GitHubWorkflowRefExtension | undefined;
    get extBuildSignerURI(): X509BuildSignerURIExtension | undefined;
    get extBuildSignerDigest(): X509BuildSignerDigestExtension | undefined;
    get extRunnerEnvironment(): X509RunnerEnvironmentExtension | undefined;
    get extSourceRepositoryURI(): X509SourceRepositoryURIExtension | undefined;
    get extSourceRepositoryDigest(): X509SourceRepositoryDigestExtension | undefined;
    get extSourceRepositoryRef(): X509SourceRepositoryRefExtension | undefined;
    get extSourceRepositoryIdentifier(): X509SourceRepositoryIdentifierExtension | undefined;
    get extSourceRepositoryOwnerURI(): X509SourceRepositoryOwnerURIExtension | undefined;
    get extSourceRepositoryOwnerIdentifier(): X509SourceRepositoryOwnerIdentifierExtension | undefined;
    get extBuildConfigURI(): X509BuildConfigURIExtension | undefined;
    get extBuildConfigDigest(): X509BuildConfigDigestExtension | undefined;
    get extBuildTrigger(): X509BuildTriggerExtension | undefined;
    get extRunInvocationURI(): X509RunInvocationURIExtension | undefined;
    get extSourceRepositoryVisibility(): X509SourceRepositoryVisibilityExtension | undefined;
    get isCA(): boolean;
    extension(oid: string): X509Extension | undefined;
    verify(issuerCertificate?: X509Certificate): Promise<boolean>;
    validForDate(date: Date): boolean;
    equals(other: X509Certificate): boolean;
    clone(): X509Certificate;
    private findExtension;
    private get tbsCertificateObj();
    private get signatureAlgorithmObj();
    private get signatureValueObj();
    private get versionObj();
    private get serialNumberObj();
    private get issuerObj();
    private get validityObj();
    private get subjectObj();
    private get subjectPublicKeyInfoObj();
    private get extensionsObj();
    private parseDistinguishedName;
}
