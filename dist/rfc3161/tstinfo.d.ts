import { ASN1Obj } from "@freedomofpress/crypto-browser";
export declare class TSTInfo {
    root: ASN1Obj;
    constructor(asn1: ASN1Obj);
    get version(): bigint;
    get genTime(): Date;
    get messageImprintHashAlgorithm(): string;
    get messageImprintHashedMessage(): Uint8Array;
    get raw(): Uint8Array;
    verify(data: Uint8Array): Promise<void>;
    private get messageImprintObj();
}
