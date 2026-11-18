import type { TLogEntry } from "../bundle.js";
import type { RekorKeyInfo } from "../interfaces.js";
export interface TLogSignature {
    name: string;
    keyHint: Uint8Array;
    signature: Uint8Array;
}
export declare class SignedNote {
    readonly note: string;
    readonly signatures: TLogSignature[];
    constructor(note: string, signatures: TLogSignature[]);
    static fromString(envelope: string): SignedNote;
}
export declare class LogCheckpoint {
    readonly origin: string;
    readonly logSize: bigint;
    readonly logHash: Uint8Array;
    readonly rest: string[];
    constructor(origin: string, logSize: bigint, logHash: Uint8Array, rest: string[]);
    static fromString(note: string): LogCheckpoint;
}
export declare function verifyCheckpoint(entry: TLogEntry, log: RekorKeyInfo): Promise<void>;
