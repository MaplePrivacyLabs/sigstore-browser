interface SCTOptions {
    version: number;
    logID: Uint8Array;
    timestamp: Uint8Array;
    extensions: Uint8Array;
    hashAlgorithm: number;
    signatureAlgorithm: number;
    signature: Uint8Array;
}
export declare class SignedCertificateTimestamp {
    readonly version: number;
    readonly logID: Uint8Array;
    readonly timestamp: Uint8Array;
    readonly extensions: Uint8Array;
    readonly hashAlgorithm: number;
    readonly signatureAlgorithm: number;
    readonly signature: Uint8Array;
    constructor(options: SCTOptions);
    get datetime(): Date;
    get algorithm(): string;
    verify(preCert: Uint8Array, key: CryptoKey): Promise<boolean>;
    static parse(buf: Uint8Array): SignedCertificateTimestamp;
}
export {};
