import { X509Certificate } from "./x509/index.js";
export declare function parseValidityPeriod(validity: {
    start?: unknown;
    end?: unknown;
} | undefined): {
    start: Date;
    end: Date;
};
export declare enum SigstoreRoots {
    certificateAuthorities = "certificateAuthorities",
    ctlogs = "ctlogs",
    timestampAuthorities = "timestampAuthorities",
    tlogs = "tlogs"
}
export type RawTimestampAuthorities = RawTimestampAuthority[];
export interface TrustedRoot {
    mediaType: string;
    tlogs: RawLogs;
    certificateAuthorities: RawCAs;
    ctlogs: RawLogs;
    timestampAuthorities: RawTimestampAuthorities;
}
export interface RawTimestampAuthority {
    subject: {
        organization: string;
        commonName: string;
    };
    certChain: {
        certificates: {
            rawBytes: string;
        }[];
    };
    validFor: {
        start: string;
        end?: string;
    };
    operator?: string;
}
export interface CTLog {
    logID: Uint8Array;
    publicKey: CryptoKey;
    operator: string;
    validFor: {
        start: Date;
        end: Date;
    };
}
export interface RekorKeyInfo {
    publicKey: CryptoKey;
    logId: Uint8Array;
    hashAlgorithm: string;
    operator: string;
    validFor: {
        start: Date;
        end: Date;
    };
}
export interface CertAuthority {
    certChain: X509Certificate[];
    validFor: {
        start: Date;
        end: Date;
    };
}
export interface Sigstore {
    rekor: RekorKeyInfo[];
    ctlogs: CTLog[];
    certificateAuthorities: CertAuthority[];
}
export interface RawLog {
    baseUrl: string;
    hashAlgorithm: string;
    publicKey: {
        rawBytes: string;
        keyDetails: string;
        validFor: {
            start: string;
            end?: string;
        };
    };
    logId: {
        keyId: string;
    };
    operator?: string;
}
export type RawLogs = RawLog[];
export interface RawCA {
    subject: {
        organization: string;
        commonName: string;
    };
    uri: string;
    certChain: {
        certificates: {
            rawBytes: string;
        }[];
    };
    validFor: {
        start: string;
        end?: string;
    };
}
export type RawCAs = RawCA[];
export { EcdsaTypes, HashAlgorithms, KeyTypes } from "@freedomofpress/crypto-browser";
export declare function getHashAlgorithm(algorithm: string): string;
