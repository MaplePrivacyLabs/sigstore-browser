// `code` says which check failed: the imprint (another message) or the signature over the token.
export class RFC3161TimestampVerificationError extends Error {
    constructor(message, code = "timestamp-malformed") {
        super(message);
        this.code = code;
    }
}
//# sourceMappingURL=error.js.map