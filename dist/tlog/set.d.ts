import type { TLogEntry } from "../bundle.js";
import type { RekorKeyInfo } from "../interfaces.js";
export declare function verifyInclusionPromise(entry: TLogEntry, promise: string, log: RekorKeyInfo): Promise<Date>;
