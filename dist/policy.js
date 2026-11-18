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
import { PolicyError } from "./errors.js";
import { EXTENSION_OID_BUILD_CONFIG_DIGEST, EXTENSION_OID_BUILD_CONFIG_URI, EXTENSION_OID_BUILD_SIGNER_DIGEST, EXTENSION_OID_BUILD_SIGNER_URI, EXTENSION_OID_BUILD_TRIGGER, EXTENSION_OID_FULCIO_ISSUER_V1, EXTENSION_OID_FULCIO_ISSUER_V2, EXTENSION_OID_GITHUB_WORKFLOW_NAME, EXTENSION_OID_GITHUB_WORKFLOW_REF, EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY, EXTENSION_OID_GITHUB_WORKFLOW_SHA, EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER, EXTENSION_OID_OTHERNAME, EXTENSION_OID_RUN_INVOCATION_URI, EXTENSION_OID_RUNNER_ENVIRONMENT, EXTENSION_OID_SOURCE_REPOSITORY_DIGEST, EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER, EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER, EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI, EXTENSION_OID_SOURCE_REPOSITORY_REF, EXTENSION_OID_SOURCE_REPOSITORY_URI, EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY, } from "./x509/cert.js";
// Standard GitHub Actions OIDC issuer
// https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
/**
 * Base class for V1 extension policies (raw OCTET STRING value).
 */
class SingleX509ExtPolicyV1 {
    constructor(value) {
        this.expectedValue = value;
    }
    verify(cert) {
        const extValue = this.getExtensionValue(cert);
        if (extValue === undefined) {
            throw new PolicyError(`Certificate does not contain ${this.name} (${this.oid}) extension`);
        }
        if (extValue !== this.expectedValue) {
            throw new PolicyError(`Certificate's ${this.name} does not match ` +
                `(got '${extValue}', expected '${this.expectedValue}')`);
        }
    }
}
/**
 * Base class for V2 extension policies (DER-encoded UTF8String).
 * Uses the same verify logic as V1 since our extension classes handle the parsing.
 */
class SingleX509ExtPolicyV2 extends SingleX509ExtPolicyV1 {
}
// ============================================================================
// V1 Extension Policies (OID 1.3.6.1.4.1.57264.1.1 - 1.3.6.1.4.1.57264.1.6)
// ============================================================================
/**
 * Verifies the certificate's OIDC issuer (V1 format).
 * OID: 1.3.6.1.4.1.57264.1.1
 */
export class OIDCIssuer extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_FULCIO_ISSUER_V1;
        this.name = "OIDCIssuer";
    }
    getExtensionValue(cert) {
        return cert.extFulcioIssuerV1?.issuer;
    }
}
/**
 * Verifies the certificate's GitHub Actions workflow trigger.
 * OID: 1.3.6.1.4.1.57264.1.2
 */
export class GitHubWorkflowTrigger extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER;
        this.name = "GitHubWorkflowTrigger";
    }
    getExtensionValue(cert) {
        return cert.extGitHubWorkflowTrigger?.workflowTrigger;
    }
}
/**
 * Verifies the certificate's GitHub Actions workflow commit SHA.
 * OID: 1.3.6.1.4.1.57264.1.3
 */
export class GitHubWorkflowSHA extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_GITHUB_WORKFLOW_SHA;
        this.name = "GitHubWorkflowSHA";
    }
    getExtensionValue(cert) {
        return cert.extGitHubWorkflowSHA?.workflowSHA;
    }
}
/**
 * Verifies the certificate's GitHub Actions workflow name.
 * OID: 1.3.6.1.4.1.57264.1.4
 */
export class GitHubWorkflowName extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_GITHUB_WORKFLOW_NAME;
        this.name = "GitHubWorkflowName";
    }
    getExtensionValue(cert) {
        return cert.extGitHubWorkflowName?.workflowName;
    }
}
/**
 * Verifies the certificate's GitHub Actions workflow repository.
 * OID: 1.3.6.1.4.1.57264.1.5
 */
export class GitHubWorkflowRepository extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY;
        this.name = "GitHubWorkflowRepository";
    }
    getExtensionValue(cert) {
        return cert.extGitHubWorkflowRepository?.workflowRepository;
    }
}
/**
 * Verifies the certificate's GitHub Actions workflow ref.
 * OID: 1.3.6.1.4.1.57264.1.6
 */
export class GitHubWorkflowRef extends SingleX509ExtPolicyV1 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_GITHUB_WORKFLOW_REF;
        this.name = "GitHubWorkflowRef";
    }
    getExtensionValue(cert) {
        return cert.extGitHubWorkflowRef?.workflowRef;
    }
}
// ============================================================================
// V2 Extension Policies (OID 1.3.6.1.4.1.57264.1.8 - 1.3.6.1.4.1.57264.1.22)
// ============================================================================
/**
 * Verifies the certificate's OIDC issuer (V2 format, DER-encoded).
 * OID: 1.3.6.1.4.1.57264.1.8
 */
export class OIDCIssuerV2 extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_FULCIO_ISSUER_V2;
        this.name = "OIDCIssuerV2";
    }
    getExtensionValue(cert) {
        return cert.extFulcioIssuerV2?.issuer;
    }
}
/**
 * Verifies the certificate's Build Signer URI.
 * OID: 1.3.6.1.4.1.57264.1.9
 */
export class OIDCBuildSignerURI extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_BUILD_SIGNER_URI;
        this.name = "OIDCBuildSignerURI";
    }
    getExtensionValue(cert) {
        return cert.extBuildSignerURI?.buildSignerURI;
    }
}
/**
 * Verifies the certificate's Build Signer Digest.
 * OID: 1.3.6.1.4.1.57264.1.10
 */
export class OIDCBuildSignerDigest extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_BUILD_SIGNER_DIGEST;
        this.name = "OIDCBuildSignerDigest";
    }
    getExtensionValue(cert) {
        return cert.extBuildSignerDigest?.buildSignerDigest;
    }
}
/**
 * Verifies the certificate's Runner Environment.
 * OID: 1.3.6.1.4.1.57264.1.11
 */
export class OIDCRunnerEnvironment extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_RUNNER_ENVIRONMENT;
        this.name = "OIDCRunnerEnvironment";
    }
    getExtensionValue(cert) {
        return cert.extRunnerEnvironment?.runnerEnvironment;
    }
}
/**
 * Verifies the certificate's Source Repository URI.
 * OID: 1.3.6.1.4.1.57264.1.12
 */
export class OIDCSourceRepositoryURI extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_URI;
        this.name = "OIDCSourceRepositoryURI";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryURI?.sourceRepositoryURI;
    }
}
/**
 * Verifies the certificate's Source Repository Digest.
 * OID: 1.3.6.1.4.1.57264.1.13
 */
export class OIDCSourceRepositoryDigest extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_DIGEST;
        this.name = "OIDCSourceRepositoryDigest";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryDigest?.sourceRepositoryDigest;
    }
}
/**
 * Verifies the certificate's Source Repository Ref.
 * OID: 1.3.6.1.4.1.57264.1.14
 */
export class OIDCSourceRepositoryRef extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_REF;
        this.name = "OIDCSourceRepositoryRef";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryRef?.sourceRepositoryRef;
    }
}
/**
 * Verifies the certificate's Source Repository Identifier.
 * OID: 1.3.6.1.4.1.57264.1.15
 */
export class OIDCSourceRepositoryIdentifier extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER;
        this.name = "OIDCSourceRepositoryIdentifier";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryIdentifier?.sourceRepositoryIdentifier;
    }
}
/**
 * Verifies the certificate's Source Repository Owner URI.
 * OID: 1.3.6.1.4.1.57264.1.16
 */
export class OIDCSourceRepositoryOwnerURI extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI;
        this.name = "OIDCSourceRepositoryOwnerURI";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryOwnerURI?.sourceRepositoryOwnerURI;
    }
}
/**
 * Verifies the certificate's Source Repository Owner Identifier.
 * OID: 1.3.6.1.4.1.57264.1.17
 */
export class OIDCSourceRepositoryOwnerIdentifier extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER;
        this.name = "OIDCSourceRepositoryOwnerIdentifier";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryOwnerIdentifier?.sourceRepositoryOwnerIdentifier;
    }
}
/**
 * Verifies the certificate's Build Config URI.
 * OID: 1.3.6.1.4.1.57264.1.18
 */
export class OIDCBuildConfigURI extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_BUILD_CONFIG_URI;
        this.name = "OIDCBuildConfigURI";
    }
    getExtensionValue(cert) {
        return cert.extBuildConfigURI?.buildConfigURI;
    }
}
/**
 * Verifies the certificate's Build Config Digest.
 * OID: 1.3.6.1.4.1.57264.1.19
 */
export class OIDCBuildConfigDigest extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_BUILD_CONFIG_DIGEST;
        this.name = "OIDCBuildConfigDigest";
    }
    getExtensionValue(cert) {
        return cert.extBuildConfigDigest?.buildConfigDigest;
    }
}
/**
 * Verifies the certificate's Build Trigger.
 * OID: 1.3.6.1.4.1.57264.1.20
 */
export class OIDCBuildTrigger extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_BUILD_TRIGGER;
        this.name = "OIDCBuildTrigger";
    }
    getExtensionValue(cert) {
        return cert.extBuildTrigger?.buildTrigger;
    }
}
/**
 * Verifies the certificate's Run Invocation URI.
 * OID: 1.3.6.1.4.1.57264.1.21
 */
export class OIDCRunInvocationURI extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_RUN_INVOCATION_URI;
        this.name = "OIDCRunInvocationURI";
    }
    getExtensionValue(cert) {
        return cert.extRunInvocationURI?.runInvocationURI;
    }
}
/**
 * Verifies the certificate's Source Repository Visibility at signing.
 * OID: 1.3.6.1.4.1.57264.1.22
 */
export class OIDCSourceRepositoryVisibility extends SingleX509ExtPolicyV2 {
    constructor() {
        super(...arguments);
        this.oid = EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY;
        this.name = "OIDCSourceRepositoryVisibility";
    }
    getExtensionValue(cert) {
        return cert.extSourceRepositoryVisibility?.sourceRepositoryVisibility;
    }
}
// ============================================================================
// Policy Combinators
// ============================================================================
/**
 * The "any of" policy, corresponding to a logical OR between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export class AnyOf {
    constructor(children) {
        this.children = children;
    }
    async verify(cert) {
        for (const child of this.children) {
            try {
                await child.verify(cert);
                return;
            }
            catch {
                // Continue to next policy
            }
        }
        throw new PolicyError(`0 of ${this.children.length} policies succeeded`);
    }
}
/**
 * The "all of" policy, corresponding to a logical AND between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export class AllOf {
    constructor(children) {
        this.children = children;
    }
    async verify(cert) {
        if (this.children.length < 1) {
            throw new PolicyError("no child policies to verify");
        }
        for (const child of this.children) {
            await child.verify(cert);
        }
    }
}
// ============================================================================
// Identity Policy
// ============================================================================
/**
 * Verifies the certificate's "identity", corresponding to the X.509v3 SAN.
 *
 * Identities can be verified modulo an OIDC issuer, to prevent an unexpected
 * issuer from offering a particular identity.
 *
 * Supported SAN types include emails, URIs, and Sigstore-specific "other names".
 */
export class Identity {
    constructor(options) {
        this.identity = options.identity;
        this.issuerPolicy = options.issuer ? new OIDCIssuer(options.issuer) : null;
    }
    verify(cert) {
        if (this.issuerPolicy) {
            this.issuerPolicy.verify(cert);
        }
        const sanExt = cert.extSubjectAltName;
        if (!sanExt) {
            throw new PolicyError("Certificate does not contain SubjectAlternativeName extension");
        }
        const allSans = new Set();
        // Add email (rfc822Name)
        if (sanExt.rfc822Name) {
            allSans.add(sanExt.rfc822Name);
        }
        // Add URI
        if (sanExt.uri) {
            allSans.add(sanExt.uri);
        }
        // Add Sigstore-specific otherName
        const otherName = sanExt.otherName(EXTENSION_OID_OTHERNAME);
        if (otherName) {
            allSans.add(otherName);
        }
        if (!allSans.has(this.identity)) {
            throw new PolicyError(`Certificate's SANs do not match ${this.identity}; actual SANs: ${Array.from(allSans).join(", ")}`);
        }
    }
}
//# sourceMappingURL=policy.js.map