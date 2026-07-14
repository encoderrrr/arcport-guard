import { readFile, readdir, stat } from "node:fs/promises";
import { extname, relative, resolve } from "node:path";
import { rules, SEVERITY_RANK } from "./rules.js";

const LANGUAGE_BY_EXTENSION = {
  ".sol": "solidity",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
};

const DEFAULT_IGNORES = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "cache",
  "artifacts",
  "coverage",
]);

export async function scanPath(inputPath, options = {}) {
  const root = resolve(inputPath);
  const files = await collectFiles(root, new Set([...(options.ignore ?? []), ...DEFAULT_IGNORES]));
  const findings = [];

  for (const file of files) {
    const language = LANGUAGE_BY_EXTENSION[extname(file).toLowerCase()];
    if (!language) continue;
    const source = await readFile(file, "utf8");
    const lineStarts = buildLineStarts(source);

    for (const rule of rules) {
      if (!rule.languages.includes(language)) continue;
      if (options.disabledRules?.has(rule.id)) continue;
      for (const offset of rule.detect(source)) {
        const location = locateOffset(source, lineStarts, offset);
        if (isSuppressed(source, lineStarts, location.line, rule.id)) continue;
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          message: rule.message,
          suggestion: rule.suggestion,
          docs: rule.docs,
          file: relative(process.cwd(), file) || file,
          absoluteFile: file,
          line: location.line,
          column: location.column,
          snippet: location.snippet,
        });
      }
    }
  }

  findings.sort(compareFindings);
  return { root, filesScanned: files.length, findings };
}

function isSuppressed(source, lineStarts, lineNumber, ruleId) {
  const lineIndex = lineNumber - 1;
  const candidates = [lineIndex, lineIndex - 1]
    .filter((index) => index >= 0)
    .map((index) => {
      const start = lineStarts[index];
      const end = source.indexOf("\n", start);
      return source.slice(start, end === -1 ? source.length : end);
    });
  return candidates.some((line) => {
    const match = line.match(/arcport-ignore(?:-next-line)?\s+([A-Z0-9, ]+)/i);
    if (!match) return false;
    const ignored = match[1].split(/[\s,]+/).map((value) => value.toUpperCase());
    return ignored.includes(ruleId) || ignored.includes("ALL");
  });
}

async function collectFiles(root, ignored) {
  const rootStat = await stat(root);
  if (rootStat.isFile()) return LANGUAGE_BY_EXTENSION[extname(root).toLowerCase()] ? [root] : [];

  const files = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && ignored.has(entry.name)) continue;
    const fullPath = resolve(root, entry.name);
    if (entry.isDirectory()) files.push(...(await collectFiles(fullPath, ignored)));
    else if (entry.isFile() && LANGUAGE_BY_EXTENSION[extname(entry.name).toLowerCase()]) files.push(fullPath);
  }
  return files;
}

function buildLineStarts(source) {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

function locateOffset(source, lineStarts, offset) {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if (lineStarts[middle] <= offset) low = middle + 1;
    else high = middle - 1;
  }
  const lineIndex = Math.max(0, high);
  const lineStart = lineStarts[lineIndex];
  const lineEnd = source.indexOf("\n", lineStart);
  return {
    line: lineIndex + 1,
    column: offset - lineStart + 1,
    snippet: source.slice(lineStart, lineEnd === -1 ? source.length : lineEnd).trimEnd(),
  };
}

function compareFindings(a, b) {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.ruleId.localeCompare(b.ruleId)
  );
}
