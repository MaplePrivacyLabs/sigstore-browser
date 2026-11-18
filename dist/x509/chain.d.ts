import { X509Certificate } from "./cert.js";
interface CertificateChainVerifierOptions {
    trustedCerts: X509Certificate[];
    untrustedCert: X509Certificate;
    timestamp: Date;
}
export declare class CertificateChainVerifier {
    private untrustedCert;
    private trustedCerts;
    private localCerts;
    private timestamp;
    constructor(opts: CertificateChainVerifierOptions);
    verify(): Promise<X509Certificate[]>;
    private sort;
    private buildPaths;
    private findIssuer;
    private checkPath;
}
export {};
