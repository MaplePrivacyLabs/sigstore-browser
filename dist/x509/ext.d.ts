import { ASN1Obj } from "@freedomofpress/crypto-browser";
import { SignedCertificateTimestamp } from "./sct.js";
export declare class X509Extension {
    protected root: ASN1Obj;
    constructor(asn1: ASN1Obj);
    get oid(): string;
    get critical(): boolean;
    get value(): Uint8Array;
    get valueObj(): ASN1Obj;
    protected get extnValueObj(): ASN1Obj;
}
export declare class X509BasicConstraintsExtension extends X509Extension {
    get isCA(): boolean;
    get pathLenConstraint(): bigint | undefined;
    private get sequence();
}
export declare class X509KeyUsageExtension extends X509Extension {
    get digitalSignature(): boolean;
    get keyCertSign(): boolean;
    get crlSign(): boolean;
    private get bitString();
}
export declare class X509SubjectAlternativeNameExtension extends X509Extension {
    get rfc822Name(): string | undefined;
    get uri(): string | undefined;
    otherName(oid: string): string | undefined;
    private findGeneralName;
    private get generalNames();
}
export declare class X509AuthorityKeyIDExtension extends X509Extension {
    get keyIdentifier(): Uint8Array | undefined;
    private findSequenceMember;
    private get sequence();
}
export declare class X509SubjectKeyIDExtension extends X509Extension {
    get keyIdentifier(): Uint8Array;
}
declare class X509FulcioExtensionV1 extends X509Extension {
    get stringValue(): string;
}
declare class X509FulcioExtensionV2 extends X509Extension {
    get stringValue(): string;
}
export declare class X509FulcioIssuerV1 extends X509FulcioExtensionV1 {
    get issuer(): string;
}
export declare class X509GitHubWorkflowTriggerExtension extends X509FulcioExtensionV1 {
    get workflowTrigger(): string;
}
export declare class X509GitHubWorkflowSHAExtension extends X509FulcioExtensionV1 {
    get workflowSHA(): string;
}
export declare class X509GitHubWorkflowNameExtension extends X509FulcioExtensionV1 {
    get workflowName(): string;
}
export declare class X509GitHubWorkflowRepositoryExtension extends X509FulcioExtensionV1 {
    get workflowRepository(): string;
}
export declare class X509GitHubWorkflowRefExtension extends X509FulcioExtensionV1 {
    get workflowRef(): string;
}
export declare class X509FulcioIssuerV2 extends X509FulcioExtensionV2 {
    get issuer(): string;
}
export declare class X509BuildSignerURIExtension extends X509FulcioExtensionV2 {
    get buildSignerURI(): string;
}
export declare class X509BuildSignerDigestExtension extends X509FulcioExtensionV2 {
    get buildSignerDigest(): string;
}
export declare class X509RunnerEnvironmentExtension extends X509FulcioExtensionV2 {
    get runnerEnvironment(): string;
}
export declare class X509SourceRepositoryURIExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryURI(): string;
}
export declare class X509SourceRepositoryDigestExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryDigest(): string;
}
export declare class X509SourceRepositoryRefExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryRef(): string;
}
export declare class X509SourceRepositoryIdentifierExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryIdentifier(): string;
}
export declare class X509SourceRepositoryOwnerURIExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryOwnerURI(): string;
}
export declare class X509SourceRepositoryOwnerIdentifierExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryOwnerIdentifier(): string;
}
export declare class X509BuildConfigURIExtension extends X509FulcioExtensionV2 {
    get buildConfigURI(): string;
}
export declare class X509BuildConfigDigestExtension extends X509FulcioExtensionV2 {
    get buildConfigDigest(): string;
}
export declare class X509BuildTriggerExtension extends X509FulcioExtensionV2 {
    get buildTrigger(): string;
}
export declare class X509RunInvocationURIExtension extends X509FulcioExtensionV2 {
    get runInvocationURI(): string;
}
export declare class X509SourceRepositoryVisibilityExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryVisibility(): string;
}
export declare class X509SCTExtension extends X509Extension {
    constructor(asn1: ASN1Obj);
    get signedCertificateTimestamps(): SignedCertificateTimestamp[];
}
export {};
