import { TextDecoder } from "node:util";
import { canonicalize } from "./crypto.js";

const MAX_BYTES = 1_048_576;
const MAX_DEPTH = 64;
const MAX_NODES = 100_000;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const NUMBER = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;
const SPACE = /^[\t\n\r ]$/;

function checkUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new SyntaxError("JSON contains an unpaired Unicode surrogate");
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new SyntaxError("JSON contains an unpaired Unicode surrogate");
    }
  }
}

function decimalMeaning(token: string): string {
  const parts = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token)!;
  const fraction = parts[3] ?? "";
  const digits = `${parts[2]}${fraction}`.replace(/^0+/, "");
  if (!digits) return "0";
  const coefficient = digits.replace(/0+$/, "");
  const exponent = Number(parts[4] ?? 0) - fraction.length + digits.length - coefficient.length;
  return `${parts[1]}${coefficient}e${exponent}`;
}

/** Reject ambiguous transport input; retain the frozen v1 canonical serializer. */
export function parseArtifactJson(input: string | Uint8Array): unknown {
  if (typeof input !== "string" && !(input instanceof Uint8Array)) {
    throw new TypeError("JSON input must be text or UTF-8 bytes");
  }
  const bytes = typeof input === "string" ? Buffer.byteLength(input, "utf8") : input.byteLength;
  if (bytes > MAX_BYTES) throw new SyntaxError("JSON exceeds the byte limit");
  const source = typeof input === "string" ? input : UTF8.decode(input);
  checkUnicode(source);
  const stack: Array<{ close: string; keys?: Set<string> }> = [];
  let nodes = 0;
  const node = () => {
    if (++nodes > MAX_NODES) throw new SyntaxError("JSON exceeds the node limit");
    if (stack.length > MAX_DEPTH) throw new SyntaxError("JSON exceeds the depth limit");
  };

  // Lexical preflight preserves information JSON.parse would discard. Native
  // JSON.parse remains the grammar/value parser; no second serializer is used.
  for (let i = 0; i < source.length;) {
    const char = source[i]!;
    if (SPACE.test(char) || char === ":" || char === ",") { i++; continue; }
    if (char === "{" || char === "[") {
      node();
      stack.push(char === "{" ? { close: "}", keys: new Set() } : { close: "]" });
      i++;
      continue;
    }
    if (char === "}" || char === "]") {
      if (stack.pop()?.close !== char) throw new SyntaxError("JSON container mismatch");
      i++;
      continue;
    }
    if (char === '"') {
      const start = i++;
      while (i < source.length && source[i] !== '"') {
        if (source[i] === "\\") i++;
        i++;
      }
      if (i >= source.length) throw new SyntaxError("JSON string is truncated");
      const value = JSON.parse(source.slice(start, ++i)) as string;
      checkUnicode(value);
      let next = i;
      while (next < source.length && SPACE.test(source[next]!)) next++;
      if (source[next] === ":") {
        const keys = stack.at(-1)?.keys;
        if (!keys) throw new SyntaxError("JSON key outside object");
        if (keys.has(value)) throw new SyntaxError("JSON contains a duplicate object key");
        keys.add(value);
        if (keys.size > MAX_NODES) throw new SyntaxError("JSON exceeds the key limit");
      } else node();
      continue;
    }
    const token = NUMBER.exec(source.slice(i))?.[0];
    if (token !== undefined) {
      node();
      const value = Number(token);
      if (!Number.isFinite(value) || decimalMeaning(token) !== decimalMeaning(JSON.stringify(value))) {
        throw new SyntaxError("JSON number loses meaning in binary64 serialization");
      }
      i += token.length;
      continue;
    }
    const literal = ["true", "false", "null"].find((word) => source.startsWith(word, i));
    if (!literal) throw new SyntaxError("JSON token is invalid");
    node();
    i += literal.length;
  }
  if (stack.length) throw new SyntaxError("JSON container is truncated");
  const value = JSON.parse(source) as unknown;
  canonicalize(value);
  return value;
}
