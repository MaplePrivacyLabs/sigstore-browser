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
import { ByteStream, Uint8ArrayToString } from "@freedomofpress/crypto-browser";
import { SignedCertificateTimestamp } from "./sct.js";
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1
export class X509Extension {
    constructor(asn1) {
        this.root = asn1;
    }
    get oid() {
        return this.root.subs[0].toOID();
    }
    get critical() {
        // The critical field is optional and will be the second element of the
        // extension sequence if present. Default to false if not present.
        return this.root.subs.length === 3 ? this.root.subs[1].toBoolean() : false;
    }
    get value() {
        return this.extnValueObj.value;
    }
    get valueObj() {
        return this.extnValueObj;
    }
    get extnValueObj() {
        // The extnValue field will be the last element of the extension sequence
        return this.root.subs[this.root.subs.length - 1];
    }
}
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
export class X509BasicConstraintsExtension extends X509Extension {
    get isCA() {
        return this.sequence.subs[0]?.toBoolean() ?? false;
    }
    get pathLenConstraint() {
        return this.sequence.subs.length > 1
            ? this.sequence.subs[1].toInteger()
            : undefined;
    }
    // The extnValue field contains a single sequence wrapping the isCA and
    // pathLenConstraint.
    get sequence() {
        return this.extnValueObj.subs[0];
    }
}
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
export class X509KeyUsageExtension extends X509Extension {
    get digitalSignature() {
        return this.bitString[0] === 1;
    }
    get keyCertSign() {
        return this.bitString[5] === 1;
    }
    get crlSign() {
        return this.bitString[6] === 1;
    }
    // The extnValue field contains a single bit string which is a bit mask
    // indicating which key usages are enabled.
    get bitString() {
        return this.extnValueObj.subs[0].toBitString();
    }
}
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
export class X509SubjectAlternativeNameExtension extends X509Extension {
    get rfc822Name() {
        const rfc822Name = this.findGeneralName(0x01)?.value;
        if (rfc822Name === undefined) {
            return undefined;
        }
        else {
            return Uint8ArrayToString(rfc822Name);
        }
    }
    get uri() {
        const uri = this.findGeneralName(0x06)?.value;
        if (uri === undefined) {
            return undefined;
        }
        else {
            return Uint8ArrayToString(uri);
        }
    }
    // Retrieve the value of an otherName with the given OID.
    otherName(oid) {
        const otherName = this.findGeneralName(0x00);
        if (otherName === undefined) {
            return undefined;
        }
        // The otherName is a sequence containing an OID and a value.
        // Need to check that the OID matches the one we're looking for.
        const otherNameOID = otherName.subs[0].toOID();
        if (otherNameOID !== oid) {
            return undefined;
        }
        // The otherNameValue is a sequence containing the actual value.
        const otherNameValue = otherName.subs[1];
        return Uint8ArrayToString(otherNameValue.subs[0].value);
    }
    findGeneralName(tag) {
        return this.generalNames.find((gn) => gn.tag.isContextSpecific(tag));
    }
    // The extnValue field contains a sequence of GeneralNames.
    get generalNames() {
        return this.extnValueObj.subs[0].subs;
    }
}
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
export class X509AuthorityKeyIDExtension extends X509Extension {
    get keyIdentifier() {
        return this.findSequenceMember(0x00)?.value;
    }
    findSequenceMember(tag) {
        return this.sequence.subs.find((el) => el.tag.isContextSpecific(tag));
    }
    // The extnValue field contains a single sequence wrapping the keyIdentifier
    get sequence() {
        return this.extnValueObj.subs[0];
    }
}
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
export class X509SubjectKeyIDExtension extends X509Extension {
    get keyIdentifier() {
        return this.extnValueObj.subs[0].value;
    }
}
// Base class for Fulcio extensions with V1 format (raw OCTET STRING value)
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
class X509FulcioExtensionV1 extends X509Extension {
    get stringValue() {
        return Uint8ArrayToString(this.extnValueObj.value);
    }
}
// Base class for Fulcio extensions with V2 format (DER-encoded UTF8String)
class X509FulcioExtensionV2 extends X509Extension {
    get stringValue() {
        return Uint8ArrayToString(this.extnValueObj.subs[0].value);
    }
}
// OID 1.3.6.1.4.1.57264.1.1 - OIDC Issuer (V1)
export class X509FulcioIssuerV1 extends X509FulcioExtensionV1 {
    get issuer() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.2 - GitHub Workflow Trigger (V1)
export class X509GitHubWorkflowTriggerExtension extends X509FulcioExtensionV1 {
    get workflowTrigger() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.3 - GitHub Workflow SHA (V1)
export class X509GitHubWorkflowSHAExtension extends X509FulcioExtensionV1 {
    get workflowSHA() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.4 - GitHub Workflow Name (V1)
export class X509GitHubWorkflowNameExtension extends X509FulcioExtensionV1 {
    get workflowName() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.5 - GitHub Workflow Repository (V1)
export class X509GitHubWorkflowRepositoryExtension extends X509FulcioExtensionV1 {
    get workflowRepository() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.6 - GitHub Workflow Ref (V1)
export class X509GitHubWorkflowRefExtension extends X509FulcioExtensionV1 {
    get workflowRef() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.8 - OIDC Issuer (V2)
export class X509FulcioIssuerV2 extends X509FulcioExtensionV2 {
    get issuer() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.9 - Build Signer URI (V2)
export class X509BuildSignerURIExtension extends X509FulcioExtensionV2 {
    get buildSignerURI() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.10 - Build Signer Digest (V2)
export class X509BuildSignerDigestExtension extends X509FulcioExtensionV2 {
    get buildSignerDigest() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.11 - Runner Environment (V2)
export class X509RunnerEnvironmentExtension extends X509FulcioExtensionV2 {
    get runnerEnvironment() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.12 - Source Repository URI (V2)
export class X509SourceRepositoryURIExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryURI() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.13 - Source Repository Digest (V2)
export class X509SourceRepositoryDigestExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryDigest() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.14 - Source Repository Ref (V2)
export class X509SourceRepositoryRefExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryRef() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.15 - Source Repository Identifier (V2)
export class X509SourceRepositoryIdentifierExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryIdentifier() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.16 - Source Repository Owner URI (V2)
export class X509SourceRepositoryOwnerURIExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryOwnerURI() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.17 - Source Repository Owner Identifier (V2)
export class X509SourceRepositoryOwnerIdentifierExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryOwnerIdentifier() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.18 - Build Config URI (V2)
export class X509BuildConfigURIExtension extends X509FulcioExtensionV2 {
    get buildConfigURI() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.19 - Build Config Digest (V2)
export class X509BuildConfigDigestExtension extends X509FulcioExtensionV2 {
    get buildConfigDigest() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.20 - Build Trigger (V2)
export class X509BuildTriggerExtension extends X509FulcioExtensionV2 {
    get buildTrigger() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.21 - Run Invocation URI (V2)
export class X509RunInvocationURIExtension extends X509FulcioExtensionV2 {
    get runInvocationURI() {
        return this.stringValue;
    }
}
// OID 1.3.6.1.4.1.57264.1.22 - Source Repository Visibility (V2)
export class X509SourceRepositoryVisibilityExtension extends X509FulcioExtensionV2 {
    get sourceRepositoryVisibility() {
        return this.stringValue;
    }
}
// https://www.rfc-editor.org/rfc/rfc6962#section-3.3
export class X509SCTExtension extends X509Extension {
    constructor(asn1) {
        super(asn1);
    }
    get signedCertificateTimestamps() {
        const buf = this.extnValueObj.subs[0].value;
        const stream = new ByteStream(buf);
        // The overall list length is encoded in the first two bytes -- note this
        // is the length of the list in bytes, NOT the number of SCTs in the list
        const end = stream.getUint16() + 2;
        const sctList = [];
        while (stream.position < end) {
            // Read the length of the next SCT
            const sctLength = stream.getUint16();
            // Slice out the bytes for the next SCT and parse it
            const sct = stream.getBlock(sctLength);
            sctList.push(SignedCertificateTimestamp.parse(sct));
        }
        if (stream.position !== end) {
            throw new Error("SCT list length does not match actual length");
        }
        return sctList;
    }
}
//# sourceMappingURL=ext.js.map