/**
 * Returns the path of the first member name that appears twice in one object
 * (for example `$.dsseEnvelope`), or undefined if there is none. Throws a
 * SyntaxError for text whose structure is not JSON or that nests deeper than 64
 * levels. Numbers, literals and string escapes are not validated here: callers
 * must still parse the text with JSON.parse.
 */
export declare function findDuplicateKey(text: string): string | undefined;
