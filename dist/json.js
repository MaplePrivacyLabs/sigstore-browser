/*
 * JSON.parse keeps the last of two members with the same name, silently. A
 * bundle that names a member twice can therefore be read differently by
 * different parsers. findDuplicateKey() scans JSON text, without building
 * values, and reports the first object member name that repeats.
 */
const MAX_DEPTH = 64;
class Scanner {
    constructor(text) {
        this.text = text;
        this.pos = 0;
    }
    // Returns the first repeated member name as a JSON path, or undefined.
    scanDocument() {
        const found = this.value("$", 0);
        this.ws();
        if (this.pos !== this.text.length)
            throw new SyntaxError("Unexpected data after JSON value");
        return found;
    }
    ws() {
        while (this.pos < this.text.length) {
            const c = this.text.charCodeAt(this.pos);
            // space, tab, line feed, carriage return
            if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d)
                return;
            this.pos++;
        }
    }
    value(path, depth) {
        if (depth > MAX_DEPTH)
            throw new SyntaxError("JSON nesting is too deep");
        this.ws();
        const c = this.text[this.pos];
        if (c === "{")
            return this.object(path, depth + 1);
        if (c === "[")
            return this.array(path, depth + 1);
        if (c === '"') {
            this.string();
            return undefined;
        }
        this.scalar();
        return undefined;
    }
    object(path, depth) {
        this.pos++; // {
        const names = new Set();
        let found;
        this.ws();
        if (this.text[this.pos] === "}") {
            this.pos++;
            return undefined;
        }
        for (;;) {
            this.ws();
            if (this.text[this.pos] !== '"')
                throw new SyntaxError("Expected a member name");
            const name = JSON.parse(this.string());
            if (found === undefined && names.has(name))
                found = `${path}.${name}`;
            names.add(name);
            this.ws();
            if (this.text[this.pos] !== ":")
                throw new SyntaxError("Expected ':'");
            this.pos++;
            const inner = this.value(`${path}.${name}`, depth);
            found ?? (found = inner);
            this.ws();
            const next = this.text[this.pos++];
            if (next === "}")
                return found;
            if (next !== ",")
                throw new SyntaxError("Expected ',' or '}'");
        }
    }
    array(path, depth) {
        this.pos++; // [
        let found;
        this.ws();
        if (this.text[this.pos] === "]") {
            this.pos++;
            return undefined;
        }
        for (let i = 0;; i++) {
            const inner = this.value(`${path}[${i}]`, depth);
            found ?? (found = inner);
            this.ws();
            const next = this.text[this.pos++];
            if (next === "]")
                return found;
            if (next !== ",")
                throw new SyntaxError("Expected ',' or ']'");
        }
    }
    // Skips a string token and returns its raw text, quotes included.
    string() {
        const start = this.pos++;
        while (this.pos < this.text.length) {
            const c = this.text[this.pos++];
            if (c === "\\") {
                this.pos++;
            }
            else if (c === '"') {
                return this.text.slice(start, this.pos);
            }
        }
        throw new SyntaxError("Unterminated string");
    }
    // Numbers and literals; JSON.parse validates them afterwards.
    scalar() {
        const start = this.pos;
        while (this.pos < this.text.length && !",]}: \t\n\r".includes(this.text[this.pos])) {
            this.pos++;
        }
        if (this.pos === start)
            throw new SyntaxError("Expected a JSON value");
    }
}
/**
 * Returns the path of the first member name that appears twice in one object
 * (for example `$.dsseEnvelope`), or undefined if there is none. Throws a
 * SyntaxError for text whose structure is not JSON or that nests deeper than 64
 * levels. Numbers, literals and string escapes are not validated here: callers
 * must still parse the text with JSON.parse.
 */
export function findDuplicateKey(text) {
    return new Scanner(text).scanDocument();
}
//# sourceMappingURL=json.js.map