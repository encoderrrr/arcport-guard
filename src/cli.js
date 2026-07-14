#!/usr/bin/env node

import { loadConfig } from "./config.js";
import { filterFindings, formatJson, formatText } from "./reporters.js";
import { SEVERITY_RANK } from "./rules.js";
import { scanPath } from "./scanner.js";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h") || args[0] === "help") {
  printHelp();
  process.exit(0);
}

if (args.includes("--version") || args.includes("-v")) {
  console.log("0.1.0");
  process.exit(0);
}

const command = args[0] && !args[0].startsWith("-") ? args.shift() : "scan";
if (command !== "scan") {
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(2);
}

const options = parseOptions(args);

try {
  const config = await loadConfig(options.config);
  const result = await scanPath(options.path, config);
  result.findings = filterFindings(result.findings, options.minimumSeverity);

  if (options.format === "json") console.log(formatJson(result));
  else console.log(formatText(result, { color: options.color }));

  const shouldFail = result.findings.some(
    (finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[options.failOn],
  );
  process.exitCode = shouldFail ? 1 : 0;
} catch (error) {
  console.error(`ArcPort failed: ${error.message}`);
  process.exitCode = 2;
}

function parseOptions(values) {
  const options = {
    path: ".",
    format: "text",
    minimumSeverity: "low",
    failOn: "high",
    config: undefined,
    color: process.stdout.isTTY,
  };

  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("-") && options.path === ".") options.path = value;
    else if (value === "--format") options.format = requireValue(values, ++index, value);
    else if (value === "--min-severity") options.minimumSeverity = requireValue(values, ++index, value);
    else if (value === "--fail-on") options.failOn = requireValue(values, ++index, value);
    else if (value === "--config") options.config = requireValue(values, ++index, value);
    else if (value === "--no-color") options.color = false;
    else throw new Error(`Unknown option: ${value}`);
  }

  if (!new Set(["text", "json"]).has(options.format)) throw new Error("--format must be text or json");
  for (const field of ["minimumSeverity", "failOn"]) {
    if (!(options[field] in SEVERITY_RANK)) throw new Error(`${field} must be critical, high, medium, low, or info`);
  }
  return options;
}

function requireValue(values, index, option) {
  if (!values[index]) throw new Error(`${option} needs a value`);
  return values[index];
}

function printHelp() {
  console.log(`ArcPort Guard 0.1.0

Usage:
  arcport scan [path] [options]

Options:
  --format text|json          Output format (default: text)
  --min-severity <level>      Hide findings below this level (default: low)
  --fail-on <level>           Exit 1 at or above this level (default: high)
  --config <path>             JSON config with ignore and disabledRules
  --no-color                  Disable ANSI colors
  -h, --help                  Show help
  -v, --version               Show version`);
}
