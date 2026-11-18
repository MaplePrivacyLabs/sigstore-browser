import type { SigstoreBundle, TLogEntry } from "../bundle.js";
import { ManagedPublicKey } from "../key.js";
import { X509Certificate } from "../x509/cert.js";
export interface RekorEntry {
    apiVersion: string;
    kind: string;
    spec: unknown;
}
export type LogSigner = X509Certificate | ManagedPublicKey;
export declare function verifyTLogBody(entry: TLogEntry, bundle: SigstoreBundle, signer: LogSigner): Promise<void>;
export declare function assertLoggedSigner(signer: LogSigner, encoded: unknown): void;
export interface V2Verifier {
    x509Certificate?: {
        rawBytes?: string;
    };
    publicKey?: {
        rawBytes?: string;
    };
    keyDetails?: string;
}
/**
 * Compares the verifier recorded in a Rekor v2 entry with the signer. For a managed key, the
 * recorded key details must name the curve of the recorded key, which must be the signer's key.
 */
export declare function assertLoggedV2Verifier(signer: LogSigner, verifier: V2Verifier | undefined): void;
export declare function assertLoggedCertificate(cert: X509Certificate, encoded: unknown, pem: boolean): void;
