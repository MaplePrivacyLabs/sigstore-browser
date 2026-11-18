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
import { digest, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { HashAlgorithms } from "../interfaces.js";
import { SHA2_HASH_ALGOS } from "../oid.js";
import { RFC3161TimestampVerificationError } from "./error.js";
export class TSTInfo {
    constructor(asn1) {
        this.root = asn1;
    }
    get version() {
        return this.root.subs[0].toInteger();
    }
    get genTime() {
        return this.root.subs[4].toDate();
    }
    get messageImprintHashAlgorithm() {
        const oid = this.messageImprintObj.subs[0].subs[0].toOID();
        const algo = SHA2_HASH_ALGOS[oid];
        if (!algo) {
            throw new Error(`Unknown message imprint hash algorithm OID: ${oid}`);
        }
        return algo;
    }
    get messageImprintHashedMessage() {
        return this.messageImprintObj.subs[1].value;
    }
    get raw() {
        return this.root.toDER();
    }
    async verify(data) {
        const hashAlg = this.messageImprintHashAlgorithm;
        // Convert hash algorithm name to the format expected by WebCrypto
        const hashAlgName = hashAlg === "sha256" ? HashAlgorithms.SHA256 :
            hashAlg === "sha384" ? HashAlgorithms.SHA384 :
                hashAlg === "sha512" ? HashAlgorithms.SHA512 : hashAlg;
        if (!uint8ArrayEqual(await digest(hashAlgName, data), this.messageImprintHashedMessage)) {
            throw new RFC3161TimestampVerificationError("message imprint does not match artifact", "timestamp-message-mismatch");
        }
    }
    // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
    get messageImprintObj() {
        return this.root.subs[2];
    }
}
//# sourceMappingURL=tstinfo.js.map