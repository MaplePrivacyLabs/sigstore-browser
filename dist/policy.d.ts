/**
 * Adapted from sigstore-python sigstore/verify/policy.py
 *
 * This module provides policy verification for checking certificate identity claims.
 * Each policy class verifies a specific X.509 extension value against an expected value.
 *
 * There are two types of extension formats:
 * - V1 extensions: Raw OCTET STRING containing the value directly
 * - V2 extensions: DER-encoded UTF8String (RFC 5280 compliant)
 *
 * Policies can be combined using:
 * - AllOf: All child policies must pass (logical AND)
 * - AnyOf: At least one child policy must pass (logical OR)
 * - Identity: Verifies SAN with optional issuer check
 */
import { X509Certificate } from "./x509/cert.js";
export declare const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
/**
 * Interface that all verification policies conform to.
 */
export interface VerificationPolicy {
    verify(cert: X509Certificate): void | Promise<void>;
}
/**
 * Base class for V1 extension policies (raw OCTET STRING value).
 */
declare abstract class SingleX509ExtPolicyV1 implements VerificationPolicy {
    abstract readonly oid: string;
    abstract readonly name: string;
    protected readonly expectedValue: string;
    constructor(value: string);
    protected abstract getExtensionValue(cert: X509Certificate): string | undefined;
    verify(cert: X509Certificate): void;
}
/**
 * Base class for V2 extension policies (DER-encoded UTF8String).
 * Uses the same verify logic as V1 since our extension classes handle the parsing.
 */
declare abstract class SingleX509ExtPolicyV2 extends SingleX509ExtPolicyV1 {
}
/**
 * Verifies the certificate's OIDC issuer (V1 format).
 * OID: 1.3.6.1.4.1.57264.1.1
 */
export declare class OIDCIssuer extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.1";
    readonly name = "OIDCIssuer";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's GitHub Actions workflow trigger.
 * OID: 1.3.6.1.4.1.57264.1.2
 */
export declare class GitHubWorkflowTrigger extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.2";
    readonly name = "GitHubWorkflowTrigger";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's GitHub Actions workflow commit SHA.
 * OID: 1.3.6.1.4.1.57264.1.3
 */
export declare class GitHubWorkflowSHA extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.3";
    readonly name = "GitHubWorkflowSHA";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's GitHub Actions workflow name.
 * OID: 1.3.6.1.4.1.57264.1.4
 */
export declare class GitHubWorkflowName extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.4";
    readonly name = "GitHubWorkflowName";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's GitHub Actions workflow repository.
 * OID: 1.3.6.1.4.1.57264.1.5
 */
export declare class GitHubWorkflowRepository extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.5";
    readonly name = "GitHubWorkflowRepository";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's GitHub Actions workflow ref.
 * OID: 1.3.6.1.4.1.57264.1.6
 */
export declare class GitHubWorkflowRef extends SingleX509ExtPolicyV1 {
    readonly oid = "1.3.6.1.4.1.57264.1.6";
    readonly name = "GitHubWorkflowRef";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's OIDC issuer (V2 format, DER-encoded).
 * OID: 1.3.6.1.4.1.57264.1.8
 */
export declare class OIDCIssuerV2 extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.8";
    readonly name = "OIDCIssuerV2";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Build Signer URI.
 * OID: 1.3.6.1.4.1.57264.1.9
 */
export declare class OIDCBuildSignerURI extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.9";
    readonly name = "OIDCBuildSignerURI";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Build Signer Digest.
 * OID: 1.3.6.1.4.1.57264.1.10
 */
export declare class OIDCBuildSignerDigest extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.10";
    readonly name = "OIDCBuildSignerDigest";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Runner Environment.
 * OID: 1.3.6.1.4.1.57264.1.11
 */
export declare class OIDCRunnerEnvironment extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.11";
    readonly name = "OIDCRunnerEnvironment";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository URI.
 * OID: 1.3.6.1.4.1.57264.1.12
 */
export declare class OIDCSourceRepositoryURI extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.12";
    readonly name = "OIDCSourceRepositoryURI";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Digest.
 * OID: 1.3.6.1.4.1.57264.1.13
 */
export declare class OIDCSourceRepositoryDigest extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.13";
    readonly name = "OIDCSourceRepositoryDigest";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Ref.
 * OID: 1.3.6.1.4.1.57264.1.14
 */
export declare class OIDCSourceRepositoryRef extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.14";
    readonly name = "OIDCSourceRepositoryRef";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Identifier.
 * OID: 1.3.6.1.4.1.57264.1.15
 */
export declare class OIDCSourceRepositoryIdentifier extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.15";
    readonly name = "OIDCSourceRepositoryIdentifier";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Owner URI.
 * OID: 1.3.6.1.4.1.57264.1.16
 */
export declare class OIDCSourceRepositoryOwnerURI extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.16";
    readonly name = "OIDCSourceRepositoryOwnerURI";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Owner Identifier.
 * OID: 1.3.6.1.4.1.57264.1.17
 */
export declare class OIDCSourceRepositoryOwnerIdentifier extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.17";
    readonly name = "OIDCSourceRepositoryOwnerIdentifier";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Build Config URI.
 * OID: 1.3.6.1.4.1.57264.1.18
 */
export declare class OIDCBuildConfigURI extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.18";
    readonly name = "OIDCBuildConfigURI";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Build Config Digest.
 * OID: 1.3.6.1.4.1.57264.1.19
 */
export declare class OIDCBuildConfigDigest extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.19";
    readonly name = "OIDCBuildConfigDigest";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Build Trigger.
 * OID: 1.3.6.1.4.1.57264.1.20
 */
export declare class OIDCBuildTrigger extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.20";
    readonly name = "OIDCBuildTrigger";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Run Invocation URI.
 * OID: 1.3.6.1.4.1.57264.1.21
 */
export declare class OIDCRunInvocationURI extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.21";
    readonly name = "OIDCRunInvocationURI";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * Verifies the certificate's Source Repository Visibility at signing.
 * OID: 1.3.6.1.4.1.57264.1.22
 */
export declare class OIDCSourceRepositoryVisibility extends SingleX509ExtPolicyV2 {
    readonly oid = "1.3.6.1.4.1.57264.1.22";
    readonly name = "OIDCSourceRepositoryVisibility";
    protected getExtensionValue(cert: X509Certificate): string | undefined;
}
/**
 * The "any of" policy, corresponding to a logical OR between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export declare class AnyOf implements VerificationPolicy {
    private children;
    constructor(children: VerificationPolicy[]);
    verify(cert: X509Certificate): Promise<void>;
}
/**
 * The "all of" policy, corresponding to a logical AND between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export declare class AllOf implements VerificationPolicy {
    private children;
    constructor(children: VerificationPolicy[]);
    verify(cert: X509Certificate): Promise<void>;
}
/**
 * Verifies the certificate's "identity", corresponding to the X.509v3 SAN.
 *
 * Identities can be verified modulo an OIDC issuer, to prevent an unexpected
 * issuer from offering a particular identity.
 *
 * Supported SAN types include emails, URIs, and Sigstore-specific "other names".
 */
export declare class Identity implements VerificationPolicy {
    private identity;
    private issuerPolicy;
    constructor(options: {
        identity: string;
        issuer?: string;
    });
    verify(cert: X509Certificate): void;
}
export {};
