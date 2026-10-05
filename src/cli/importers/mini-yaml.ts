// A deliberately small YAML subset parser (AIGW-43).
//
// WHY NOT `yaml` FROM npm
//
// `cli/package.json` has `"dependencies": {}` and that is a decision, not an
// oversight: this CLI is installed globally on developer machines and on CI
// runners, and every runtime dependency is a supply-chain surface on a tool
// whose whole job is handling credentials. KnoxCall's own comparison page cites
// a March 2026 PyPI compromise of a competing LLM proxy; adding a transitive
// tree to read one config file would be a poor look and a worse risk.
//
// A LiteLLM `config.yaml` is a small, regular document — nested maps, lists of
// maps, scalars — and roughly a hundred lines covers it.
//
// THE DESIGN RULE THAT MATTERS
//
// This parser REFUSES what it does not understand instead of skipping it.
// Anchors, aliases, multi-document streams, block scalars, flow-style nesting
// beyond a simple inline list: each throws a `MiniYamlError` naming the line.
//
// That is the whole safety argument. An importer that silently drops a
// `model_list` entry it could not parse hands the operator a plan that looks
// complete and is not — they migrate, believe they are done, and discover the
// missing model in production. An importer that stops and says "line 42: block
// scalars are not supported" costs them a minute. The failure mode of refusing
// is annoyance; the failure mode of skipping is a silent gap.

export class MiniYamlError extends Error {
  constructor(message: string, readonly line: number) {
    super(`line ${line}: ${message}`);
    this.name = "MiniYamlError";
  }
}

export type YamlValue = string | number | boolean | null | YamlValue[] | { [k: string]: YamlValue };

interface Line {
  /** 1-indexed, for error messages that point at the user's file. */
  number: number;
  indent: number;
  text: string;
}

const UNSUPPORTED: Array<[RegExp, string]> = [
  [/^\s*&\S/, "YAML anchors (&name) are not supported"],
  [/:\s+\*\S/, "YAML aliases (*name) are not supported"],
  [/^\s*<<\s*:/, "YAML merge keys (<<:) are not supported"],
  [/^---\s*\S/, "multi-document YAML is not supported"],
  [/:\s*[|>][-+]?\s*$/, "block scalars (| and >) are not supported"],
  [/^\s*\?\s/, "explicit keys (? ) are not supported"],
];

function scan(source: string): Line[] {
  const out: Line[] = [];
  const rawLines = source.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i];
    const number = i + 1;
    // A document separator on its own is fine; a second document is not.
    if (/^---\s*$/.test(raw)) {
      if (out.length > 0) {
        throw new MiniYamlError("multi-document YAML is not supported", number);
      }
      continue;
    }
    if (/^\.\.\.\s*$/.test(raw)) continue;
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    if (/\t/.test(raw.slice(0, raw.length - raw.trimStart().length))) {
      throw new MiniYamlError("tabs are not valid YAML indentation", number);
    }
    for (const [re, message] of UNSUPPORTED) {
      if (re.test(raw)) throw new MiniYamlError(message, number);
    }
    out.push({ number, indent: raw.length - raw.trimStart().length, text: raw.trim() });
  }
  return out;
}

/** Strip an unquoted trailing `# comment`, honouring quotes. */
function stripComment(text: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(text[i - 1]))) {
      return text.slice(0, i).trimEnd();
    }
  }
  return text;
}

function parseScalar(raw: string, lineNumber: number): YamlValue {
  const text = stripComment(raw).trim();
  if (text === "") return null;
  if (
    (text.startsWith('"') && text.endsWith('"') && text.length > 1) ||
    (text.startsWith("'") && text.endsWith("'") && text.length > 1)
  ) {
    return text.slice(1, -1);
  }
  // A simple inline list: [a, b, c]. Nested flow collections are refused —
  // guessing at `[{a: 1}]` is exactly the kind of near-miss that produces a
  // wrong plan rather than an error.
  if (text.startsWith("[") && text.endsWith("]")) {
    const inner = text.slice(1, -1).trim();
    if (inner === "") return [];
    if (/[[\]{}]/.test(inner)) {
      throw new MiniYamlError("nested flow collections are not supported", lineNumber);
    }
    return inner.split(",").map((part) => parseScalar(part, lineNumber));
  }
  if (text.startsWith("{") && text.endsWith("}")) {
    throw new MiniYamlError("flow mappings ({a: 1}) are not supported", lineNumber);
  }
  if (text === "null" || text === "~") return null;
  if (text === "true" || text === "True") return true;
  if (text === "false" || text === "False") return false;
  if (/^-?\d+$/.test(text)) return Number(text);
  if (/^-?\d*\.\d+$/.test(text)) return Number(text);
  return text;
}

/** Split `key: value` into its two halves, honouring quoted keys. */
function splitKey(text: string, lineNumber: number): { key: string; rest: string } {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === ":" && !inSingle && !inDouble) {
      const after = text[i + 1];
      if (after === undefined || after === " ") {
        let key = text.slice(0, i).trim();
        if (
          (key.startsWith('"') && key.endsWith('"')) ||
          (key.startsWith("'") && key.endsWith("'"))
        ) {
          key = key.slice(1, -1);
        }
        if (key === "") throw new MiniYamlError("empty mapping key", lineNumber);
        return { key, rest: text.slice(i + 1).trim() };
      }
    }
  }
  throw new MiniYamlError(`expected "key: value", got ${JSON.stringify(text)}`, lineNumber);
}

function parseBlock(lines: Line[], start: number, indent: number): { value: YamlValue; next: number } {
  if (start >= lines.length) return { value: null, next: start };

  if (lines[start].text.startsWith("- ") || lines[start].text === "-") {
    const items: YamlValue[] = [];
    let i = start;
    while (i < lines.length && lines[i].indent === indent && (lines[i].text === "-" || lines[i].text.startsWith("- "))) {
      const line = lines[i];
      const inline = line.text === "-" ? "" : line.text.slice(2).trim();
      if (inline === "") {
        // `-` alone: the item is the indented block beneath it.
        const childIndent = i + 1 < lines.length ? lines[i + 1].indent : indent;
        if (i + 1 >= lines.length || childIndent <= indent) {
          items.push(null);
          i++;
          continue;
        }
        const parsed = parseBlock(lines, i + 1, childIndent);
        items.push(parsed.value);
        i = parsed.next;
        continue;
      }
      // `- key: value` starts a map whose members continue on the following
      // lines at the column the key starts in.
      if (/^[^:]+:(\s|$)/.test(inline)) {
        const keyIndent = indent + 2;
        const synthetic: Line[] = [{ number: line.number, indent: keyIndent, text: inline }];
        let j = i + 1;
        while (j < lines.length && lines[j].indent >= keyIndent) {
          synthetic.push(lines[j]);
          j++;
        }
        const parsed = parseBlock(synthetic, 0, keyIndent);
        items.push(parsed.value);
        i = j;
        continue;
      }
      items.push(parseScalar(inline, line.number));
      i++;
    }
    return { value: items, next: i };
  }

  const map: { [k: string]: YamlValue } = {};
  let i = start;
  while (i < lines.length && lines[i].indent === indent) {
    const line = lines[i];
    if (line.text.startsWith("- ")) break;
    const { key, rest } = splitKey(line.text, line.number);
    if (rest !== "") {
      map[key] = parseScalar(rest, line.number);
      i++;
      continue;
    }
    // Value is the block beneath. A list may sit at the SAME indent as its key,
    // which is the common LiteLLM style.
    const childIndex = i + 1;
    if (childIndex >= lines.length) {
      map[key] = null;
      i++;
      continue;
    }
    const child = lines[childIndex];
    if (child.indent > indent || (child.indent === indent && child.text.startsWith("- "))) {
      const parsed = parseBlock(lines, childIndex, child.indent);
      map[key] = parsed.value;
      i = parsed.next;
      continue;
    }
    map[key] = null;
    i++;
  }
  if (i === start) {
    throw new MiniYamlError(
      `unexpected indentation (expected ${indent} spaces)`,
      lines[start].number,
    );
  }
  return { value: map, next: i };
}

/**
 * Parse a YAML subset. Throws `MiniYamlError` on anything unsupported rather
 * than returning a partial document.
 */
export function parseMiniYaml(source: string): YamlValue {
  const lines = scan(source);
  if (lines.length === 0) return null;
  const { value, next } = parseBlock(lines, 0, lines[0].indent);
  if (next < lines.length) {
    throw new MiniYamlError("unexpected content after the document", lines[next].number);
  }
  return value;
}
