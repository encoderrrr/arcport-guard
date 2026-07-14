const sampleCode = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract PaymentVault {
    IERC20 public usdc;
    uint256 public lastTimestamp;

    function drawWinner() external view returns (uint256) {
        return uint256(block.prevrandao) % 100;
    }

    function balancesMatch() external view returns (bool) {
        return usdc.balanceOf(address(this)) == address(this).balance;
    }

    function processNextBlock() external view {
        require(block.timestamp > lastTimestamp, "already processed");
    }

    function closeVault() external {
        selfdestruct(payable(msg.sender));
    }
}`;

const docsBase = "https://docs.arc.io/arc/references/evm-differences";
const browserRules = [
  rule("ARC001", "high", "Native and ERC-20 USDC use different decimals", /\bbalanceOf\s*\([^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\.balance\b|\.balance\b[^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\bbalanceOf\s*\(/g, "Native USDC uses 18 decimals while its ERC-20 interface uses 6.", "Normalize both values into one named unit before comparison.", "#usdc-as-the-native-gas-token", ["sol"]),
  rule("ARC002", "critical", "PREVRANDAO is always zero on Arc", /\bblock\.(?:prevrandao|difficulty)\b|\bPREVRANDAO\b/g, "Randomness becomes predictable because Arc returns zero for PREVRANDAO.", "Use an Arc-compatible oracle or a verifiable random function.", "#execution-and-opcode-differences", ["sol"]),
  rule("ARC003", "high", "Beacon roots are unavailable on Arc", /\bparentBeaconBlockRoot\b|\bbeacon[-_ ]?roots?\b/gi, "Arc omits the EIP-4788 beacon-roots contract.", "Use an Arc-compatible oracle instead of beacon roots.", "#execution-and-opcode-differences"),
  rule("ARC004", "high", "Blob transactions are unsupported", /\bBLOBHASH\b|\bBLOBBASEFEE\b|\beip[-_]?4844\b|\btype\s*:\s*["'](?:0x)?3["']|\bblobs?\s*:/gi, "Arc rejects EIP-4844 type-3 blob transactions.", "Use calldata and a supported transaction type.", "#execution-and-opcode-differences"),
  rule("ARC005", "high", "SELFDESTRUCT has Arc-specific value rules", /\bselfdestruct\s*\(/gi, "SELFDESTRUCT moves underlying USDC and can revert for several beneficiaries.", "Remove SELFDESTRUCT or test every value path on Arc Testnet.", "#selfdestruct", ["sol"]),
  rule("ARC006", "high", "Value transfer to the zero address reverts", /address\s*\(\s*0\s*\)\s*\.(?:call|transfer|send)\b|payable\s*\(\s*address\s*\(\s*0\s*\)\s*\)/g, "Arc forbids burning native USDC through a zero-address transfer.", "Validate the recipient and use an explicit recovery address.", "#value-transfer-rules", ["sol"]),
  rule("ARC007", "medium", "Block timestamps are not strictly increasing", /(?:require\s*\(|if\s*\()[^\n;{}]*block\.timestamp\s*>\s*[A-Za-z_$][\w$]*(?:Timestamp|Time|At)\b/g, "Consecutive sub-second Arc blocks can share the same timestamp.", "Use block.number when ordering is the requirement.", "#fee-market-and-block-behavior", ["sol"]),
  rule("ARC008", "high", "USDC parsed with 18 ERC-20 decimals", /\b(?:parseUnits\s*\([^\n,]+,\s*18\s*\)|parseEther\s*\()/gi, "The Arc ERC-20 USDC interface uses 6 decimals.", "Use parseUnits(amount, 6) for ERC-20 USDC.", "#usdc-as-the-native-gas-token", ["ts", "tsx", "js", "jsx", "mjs", "cjs"], /\bUSDC\b/i),
  rule("ARC009", "medium", "Timestamp used as the primary block ordering key", /\.sort\s*\(\s*\([^)]*\)\s*=>[^\n]*(?:blockTimestamp|timestamp)[^\n]*\)/gi, "Multiple Arc blocks can have the same timestamp.", "Order by blockNumber, transactionIndex, then logIndex.", "#fee-market-and-block-behavior", ["ts", "tsx", "js", "jsx", "mjs", "cjs"]),
  rule("ARC010", "medium", "Ethereum gas symbol used for Arc", /(?:nativeCurrency|gasToken)[\s\S]{0,160}?(?:symbol|name)\s*:\s*["'](?:ETH|Ether|Ethereum)["']/gi, "Arc uses USDC, not ETH, as the native gas token.", "Label Arc native balances and fees as USDC.", "#usdc-as-the-native-gas-token", ["ts", "tsx", "js", "jsx", "mjs", "cjs"], /\bArc(?:_Testnet)?\b|chainId\s*:\s*5042002/i),
  rule("ARC011", "low", "Extra confirmations are unnecessary on Arc", /\.wait\s*\(\s*(?:[2-9]|[1-9]\d+)\s*\)/g, "Arc transactions are final on inclusion.", "Use one confirmation to avoid unnecessary latency.", "#fee-market-and-block-behavior", ["ts", "tsx", "js", "jsx", "mjs", "cjs"]),
];

function rule(id, severity, title, pattern, message, fix, anchor, extensions = null, context = null) {
  return { id, severity, title, pattern, message, fix, docs: `${docsBase}${anchor}`, extensions, context };
}

const codeInput = document.querySelector("#code-input");
const scanButton = document.querySelector("#scan-button");
const resetButton = document.querySelector("#reset-code");
const resultsList = document.querySelector("#results-list");
const resultCount = document.querySelector("#result-count");
const scanSummary = document.querySelector("#scan-summary");
const activeFile = document.querySelector("#active-file");
const fileUpload = document.querySelector("#file-upload");
const folderUpload = document.querySelector("#folder-upload");
const exportJson = document.querySelector("#export-json");
const exportMarkdown = document.querySelector("#export-markdown");

let loadedFiles = [];
let lastReport = null;

function setSample() {
  loadedFiles = [{ name: "PaymentVault.sol", source: sampleCode }];
  syncEditor();
  resetResults();
}

function syncEditor() {
  const first = loadedFiles[0];
  codeInput.value = first?.source ?? "";
  activeFile.textContent = first ? `${first.name}${loadedFiles.length > 1 ? ` +${loadedFiles.length - 1}` : ""}` : "No file";
  updateScanSummary();
}

function updateScanSummary() {
  if (loadedFiles[0]) loadedFiles[0].source = codeInput.value;
  const lines = loadedFiles.reduce((total, file) => total + file.source.split(/\r?\n/).length, 0);
  scanSummary.textContent = `${loadedFiles.length} file${loadedFiles.length === 1 ? "" : "s"} · ${lines} line${lines === 1 ? "" : "s"}`;
}

function lineFromOffset(source, offset) {
  return source.slice(0, offset).split("\n").length;
}

function extensionOf(name) {
  return name.split(".").pop().toLowerCase();
}

function scanAll() {
  updateScanSummary();
  const findings = [];

  for (const file of loadedFiles) {
    const extension = extensionOf(file.name);
    for (const check of browserRules) {
      if (check.extensions && !check.extensions.includes(extension)) continue;
      if (check.context && !check.context.test(file.source)) continue;
      check.pattern.lastIndex = 0;
      for (const match of file.source.matchAll(check.pattern)) {
        findings.push({ ...check, file: file.name, line: lineFromOffset(file.source, match.index ?? 0) });
      }
    }
  }

  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => rank[b.severity] - rank[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  lastReport = {
    tool: "ArcPort Guard browser scanner",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    filesScanned: loadedFiles.length,
    findings: findings.map(({ pattern, extensions, context, ...finding }) => finding),
  };
  renderFindings(findings);
  exportJson.disabled = false;
  exportMarkdown.disabled = false;
}

function resetResults() {
  lastReport = null;
  resultCount.textContent = "Ready";
  exportJson.disabled = true;
  exportMarkdown.disabled = true;
  resultsList.replaceChildren(emptyState("Ready to inspect", "Run the scan to reveal Arc-specific compatibility risks."));
}

function emptyState(title, message, success = false) {
  const state = document.createElement("div");
  state.className = success ? "success-state" : "empty-state";
  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.className = success ? "" : "empty-shield";
  icon.textContent = success ? "✓" : "⌁";
  const strong = document.createElement("strong");
  strong.textContent = title;
  const copy = document.createElement("p");
  copy.textContent = message;
  state.append(icon, strong, copy);
  return state;
}

function renderFindings(findings) {
  resultCount.textContent = findings.length ? `${findings.length} found` : "Clean";
  resultsList.replaceChildren();

  if (!findings.length) {
    resultsList.append(emptyState("No browser-check risks found", "Run the full CLI before deployment for all project-level checks.", true));
    return;
  }

  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = `finding-card ${finding.severity}`;
    const meta = document.createElement("div");
    meta.className = "finding-meta";
    const ruleLabel = document.createElement("span");
    ruleLabel.textContent = `${finding.severity.toUpperCase()} ${finding.id}`;
    const location = document.createElement("span");
    location.textContent = `${finding.file}:${finding.line}`;
    meta.append(ruleLabel, location);
    const title = document.createElement("h3");
    title.textContent = finding.title;
    const message = document.createElement("p");
    message.textContent = finding.message;
    const fix = document.createElement("p");
    fix.className = "finding-fix";
    const fixLabel = document.createElement("strong");
    fixLabel.textContent = "FIX ";
    fix.append(fixLabel, document.createTextNode(finding.fix));
    const docs = document.createElement("a");
    docs.className = "finding-docs";
    docs.href = finding.docs;
    docs.target = "_blank";
    docs.rel = "noreferrer";
    docs.textContent = "Arc docs ↗";
    card.append(meta, title, message, fix, docs);
    resultsList.append(card);
  }
}

async function loadSelectedFiles(fileList) {
  const accepted = [...fileList].filter((file) => ["sol", "ts", "tsx", "js", "jsx", "mjs", "cjs"].includes(extensionOf(file.name))).slice(0, 100);
  const totalBytes = accepted.reduce((sum, file) => sum + file.size, 0);
  if (!accepted.length) return showLoadError("Choose Solidity, TypeScript, or JavaScript files.");
  if (totalBytes > 5_000_000) return showLoadError("Keep the upload under 5 MB so the browser stays responsive.");
  loadedFiles = await Promise.all(accepted.map(async (file) => ({
    name: file.webkitRelativePath || file.name,
    source: await file.text(),
  })));
  syncEditor();
  resetResults();
}

function showLoadError(message) {
  resultCount.textContent = "Upload error";
  resultsList.replaceChildren(emptyState("Could not load files", message));
}

function downloadReport(format) {
  if (!lastReport) return;
  const body = format === "json" ? JSON.stringify(lastReport, null, 2) : reportAsMarkdown(lastReport);
  const blob = new Blob([body], { type: format === "json" ? "application/json" : "text/markdown" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `arcport-report.${format === "json" ? "json" : "md"}`;
  link.click();
  URL.revokeObjectURL(url);
}

function reportAsMarkdown(report) {
  const lines = ["# ArcPort Guard report", "", `Scanned ${report.filesScanned} file(s). Found ${report.findings.length} issue(s).`, ""];
  for (const finding of report.findings) {
    lines.push(`## ${finding.severity.toUpperCase()} ${finding.id}: ${finding.title}`, "", `- Location: \`${finding.file}:${finding.line}\``, `- Fix: ${finding.fix}`, `- Docs: ${finding.docs}`, "");
  }
  if (!report.findings.length) lines.push("No browser-check risks found. Run the CLI for the complete scan.");
  return lines.join("\n");
}

scanButton.addEventListener("click", scanAll);
resetButton.addEventListener("click", setSample);
fileUpload.addEventListener("change", () => loadSelectedFiles(fileUpload.files));
folderUpload.addEventListener("change", () => loadSelectedFiles(folderUpload.files));
exportJson.addEventListener("click", () => downloadReport("json"));
exportMarkdown.addEventListener("click", () => downloadReport("markdown"));
codeInput.addEventListener("input", updateScanSummary);
codeInput.addEventListener("keydown", (event) => {
  if (event.key !== "Tab") return;
  event.preventDefault();
  codeInput.setRangeText("    ", codeInput.selectionStart, codeInput.selectionEnd, "end");
  updateScanSummary();
});

const command = document.querySelector("#install-command");
for (const tab of document.querySelectorAll(".install-tabs button")) {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".install-tabs button").forEach((item) => item.setAttribute("aria-selected", "false"));
    tab.setAttribute("aria-selected", "true");
    command.textContent = tab.dataset.command;
  });
}

document.querySelector("#copy-command").addEventListener("click", async (event) => {
  try {
    await navigator.clipboard.writeText(command.textContent);
    event.currentTarget.textContent = "Copied";
    window.setTimeout(() => { event.currentTarget.textContent = "Copy"; }, 1400);
  } catch {
    event.currentTarget.textContent = "Select command";
  }
});

setSample();
