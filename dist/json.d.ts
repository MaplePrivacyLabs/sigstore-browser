/**
 * Returns the path of the first member name that appears twice in one object
 * (for example `$.dsseEnvelope`), or undefined if there is none. Throws a
 * SyntaxError for text that is not JSON or nests deeper than 64 levels. Callers
 * still parse the text with JSON.parse, which validates it fully.
 */
export declare function findDuplicateKey(text: string): string | undefined;
