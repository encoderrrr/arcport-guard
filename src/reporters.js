import { SEVERITY_RANK } from "./rules.js";

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  critical: "\u001b[35m",
  high: "\u001b[31m",
  medium: "\u001b[33m",
  low: "\u001b[36m",
  info: "\u001b[90m",
  dim: "\u001b[2m",
};

export function filterFindings(findings, minimumSeverity) {
  const threshold = SEVERITY_RANK[minimumSeverity];
  return findings.filter((finding) => SEVERITY_RANK[finding.severity] >= threshold);
}

export function formatText(result, options = {}) {
  const color = options.color !== false;
  const findings = result.findings;
  const lines = [];

  lines.push(paint("ArcPort Guard", "bold", color));
  lines.push(`Scanned ${result.filesScanned} file${result.filesScanned === 1 ? "" : "s"}.`);
  lines.push("");

  if (findings.length === 0) {
    lines.push("No Arc compatibility risks found.");
    return lines.join("\n");
  }

  for (const finding of findings) {
    const label = `${finding.severity.toUpperCase()} ${finding.ruleId}`;
    lines.push(`${paint(label, finding.severity, color)}  ${finding.file}:${finding.line}:${finding.column}`);
    lines.push(`  ${paint(finding.title, "bold", color)}`);
    lines.push(`  ${finding.message}`);
    if (finding.snippet) lines.push(`  ${paint(finding.snippet.trim(), "dim", color)}`);
    lines.push(`  Fix: ${finding.suggestion}`);
    lines.push(`  Docs: ${finding.docs}`);
    lines.push("");
  }

  const counts = countBySeverity(findings);
  lines.push(
    `Found ${findings.length} issue${findings.length === 1 ? "" : "s"}: ` +
      ["critical", "high", "medium", "low"]
        .filter((severity) => counts[severity])
        .map((severity) => `${counts[severity]} ${severity}`)
        .join(", "),
  );
  return lines.join("\n");
}

export function formatJson(result) {
  return JSON.stringify(
    {
      tool: "arcport-guard",
      version: "0.1.0",
      root: result.root,
      filesScanned: result.filesScanned,
      summary: countBySeverity(result.findings),
      findings: result.findings,
    },
    null,
    2,
  );
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function paint(value, style, enabled) {
  if (!enabled) return value;
  return `${ANSI[style] ?? ""}${value}${ANSI.reset}`;
}
