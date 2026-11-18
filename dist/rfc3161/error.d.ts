import type { ReasonCode } from "../errors.js";
export declare class RFC3161TimestampVerificationError extends Error {
    code: ReasonCode;
    constructor(message: string, code?: ReasonCode);
}
