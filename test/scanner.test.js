import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { resolve } from "node:path";
import { scanPath } from "../src/scanner.js";
import { filterFindings, formatJson } from "../src/reporters.js";

test("detects Arc-specific Solidity and TypeScript risks", async () => {
  const result = await scanPath(resolve("test/fixtures/risky"));
  const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));

  assert.equal(result.filesScanned, 2);
  assert.ok(ruleIds.has("ARC001"));
  assert.ok(ruleIds.has("ARC002"));
  assert.ok(ruleIds.has("ARC005"));
  assert.ok(ruleIds.has("ARC007"));
  assert.ok(ruleIds.has("ARC008"));
  assert.ok(ruleIds.has("ARC011"));
  assert.ok(result.findings.every((finding) => finding.line > 0 && finding.column > 0));
});

test("safe fixture has no findings", async () => {
  const result = await scanPath(resolve("test/fixtures/safe"));
  assert.equal(result.findings.length, 0);
});

test("severity filtering and JSON output work", async () => {
  const result = await scanPath(resolve("test/fixtures/risky"));
  result.findings = filterFindings(result.findings, "high");

  assert.ok(result.findings.length > 0);
  assert.ok(result.findings.every((finding) => ["high", "critical"].includes(finding.severity)));

  const report = JSON.parse(formatJson(result));
  assert.equal(report.tool, "arcport-guard");
  assert.equal(report.filesScanned, 2);
  assert.equal(report.findings.length, result.findings.length);
});

test("rules can be disabled", async () => {
  const result = await scanPath(resolve("test/fixtures/risky"), {
    ignore: [],
    disabledRules: new Set(["ARC002", "ARC005"]),
  });
  const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("ARC002"), false);
  assert.equal(ruleIds.has("ARC005"), false);
});

test("CLI returns CI-friendly exit codes", () => {
  const risky = spawnSync(
    process.execPath,
    ["src/cli.js", "scan", "test/fixtures/risky", "--no-color"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  const safe = spawnSync(
    process.execPath,
    ["src/cli.js", "scan", "test/fixtures/safe", "--no-color"],
    { cwd: process.cwd(), encoding: "utf8" },
  );

  assert.equal(risky.status, 1);
  assert.match(risky.stdout, /CRITICAL ARC002/);
  assert.equal(safe.status, 0);
  assert.match(safe.stdout, /No Arc compatibility risks found/);
});
