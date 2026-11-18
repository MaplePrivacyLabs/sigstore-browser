import type { SigstoreBundle } from "../bundle.js";
import { type LogSigner, type RekorEntry } from "./body.js";
export declare function verifyIntotoBody(entry: RekorEntry, bundle: SigstoreBundle, signer: LogSigner): Promise<void>;
