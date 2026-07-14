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
const rules = [
  {
    id: "ARC001",
    severity: "high",
    title: "Native and ERC-20 USDC use different decimals",
    extensions: ["sol"],
    languages: ["Solidity"],
    pattern: /\bbalanceOf\s*\([^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\.balance\b|\.balance\b[^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\bbalanceOf\s*\(/g,
    arcReason: "Arc exposes one underlying USDC balance through an 18-decimal native interface and a 6-decimal ERC-20 interface.",
    impact: "Raw comparison or arithmetic can be wrong by a factor of 1e12, corrupting accounting, limits, or settlement checks.",
    repair: "Choose one named application unit and normalize both values at the boundary before comparing or combining them.",
    unsafe: "usdc.balanceOf(user) == user.balance",
    safe: "const nativeUsdc = user.balance / 1e12;\nreturn usdc.balanceOf(user) == nativeUsdc;",
    docs: `${docsBase}#usdc-as-the-native-gas-token`,
    confidence: 96,
  },
  {
    id: "ARC002",
    severity: "critical",
    title: "PREVRANDAO is always zero on Arc",
    extensions: ["sol"],
    languages: ["Solidity"],
    pattern: /\bblock\.(?:prevrandao|difficulty)\b|\bPREVRANDAO\b/g,
    arcReason: "Arc returns zero for PREVRANDAO, so it cannot provide the entropy Ethereum developers may expect.",
    impact: "Lottery, assignment, or selection logic becomes predictable and can be exploited deterministically.",
    repair: "Use a trusted Arc-compatible oracle or a verifiable random function and validate its failure path.",
    unsafe: "uint256(block.prevrandao) % participants.length",
    safe: "// Request randomness from an Arc-compatible VRF\nuint256 randomValue = verifiedOracle.randomness(requestId);",
    docs: `${docsBase}#execution-and-opcode-differences`,
    confidence: 99,
  },
  {
    id: "ARC003",
    severity: "high",
    title: "Beacon roots are unavailable on Arc",
    extensions: ["sol", "ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["Solidity", "TypeScript", "JavaScript"],
    pattern: /\bparentBeaconBlockRoot\b|\bbeacon[-_ ]?roots?\b/gi,
    arcReason: "Arc does not expose Ethereum's EIP-4788 beacon-roots contract as a source of consensus data.",
    impact: "Proof verification, randomness, or application logic depending on a beacon root can return empty or invalid data.",
    repair: "Remove the beacon-root dependency and use an Arc-compatible oracle or application-specific commitment.",
    unsafe: "const root = block.parentBeaconBlockRoot;",
    safe: "const root = await arcCompatibleOracle.getCommitment(roundId);",
    docs: `${docsBase}#execution-and-opcode-differences`,
    confidence: 94,
  },
  {
    id: "ARC004",
    severity: "high",
    title: "Blob transactions are unsupported",
    extensions: ["sol", "ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["Solidity", "TypeScript", "JavaScript"],
    pattern: /\bBLOBHASH\b|\bBLOBBASEFEE\b|\beip[-_]?4844\b|\btype\s*:\s*["'](?:0x)?3["']|\bblobs?\s*:/gi,
    arcReason: "Arc rejects EIP-4844 type-3 blob transactions; blob-related opcodes do not behave like Ethereum.",
    impact: "Submission can fail outright or downstream logic can read placeholder opcode values.",
    repair: "Submit a supported transaction type and place required payload data in calldata or an Arc-supported storage path.",
    unsafe: "await wallet.sendTransaction({ type: 3, blobs });",
    safe: "await wallet.sendTransaction({ data: encodedCalldata });",
    docs: `${docsBase}#execution-and-opcode-differences`,
    confidence: 97,
  },
  {
    id: "ARC005",
    severity: "high",
    title: "SELFDESTRUCT has Arc-specific value rules",
    extensions: ["sol"],
    languages: ["Solidity"],
    pattern: /\bselfdestruct\s*\(/gi,
    arcReason: "On Arc, SELFDESTRUCT moves the contract's underlying USDC and applies beneficiary restrictions.",
    impact: "Cleanup or upgrade flows can revert for zero, self, blocklisted, or already-destroyed beneficiaries.",
    repair: "Remove SELFDESTRUCT when possible. Otherwise validate the beneficiary and test every balance path on Arc Testnet.",
    unsafe: "selfdestruct(payable(beneficiary));",
    safe: "// Prefer an explicit paused state and controlled USDC recovery\npaused = true;",
    docs: `${docsBase}#selfdestruct`,
    confidence: 99,
  },
  {
    id: "ARC006",
    severity: "high",
    title: "Value transfer to the zero address reverts",
    extensions: ["sol"],
    languages: ["Solidity"],
    pattern: /address\s*\(\s*0\s*\)\s*\.(?:call|transfer|send)\b|payable\s*\(\s*address\s*\(\s*0\s*\)\s*\)/g,
    arcReason: "Arc forbids burning native USDC through a non-zero value transfer to address(0).",
    impact: "A burn, refund, or fallback path that works elsewhere can revert and block the full transaction.",
    repair: "Reject the zero address before a native-value call and route recovery funds to an explicit governed address.",
    unsafe: "payable(address(0)).transfer(amount);",
    safe: "require(recipient != address(0), \"zero recipient\");\nrecipient.call{value: amount}(\"\");",
    docs: `${docsBase}#value-transfer-rules`,
    confidence: 98,
  },
  {
    id: "ARC007",
    severity: "medium",
    title: "Block timestamps are not strictly increasing",
    extensions: ["sol"],
    languages: ["Solidity"],
    pattern: /(?:require\s*\(|if\s*\()[^\n;{}]*block\.timestamp\s*>\s*[A-Za-z_$][\w$]*(?:Timestamp|Time|At)\b/g,
    arcReason: "Arc has sub-second blocks but one-second timestamp precision, so consecutive blocks can share a timestamp.",
    impact: "Strict timestamp ordering can reject valid later blocks or process events in an unstable order.",
    repair: "Use block.number for ordering and reserve timestamps for elapsed-time checks that allow equality.",
    unsafe: "require(block.timestamp > lastTimestamp);",
    safe: "require(block.number > lastProcessedBlock);",
    docs: `${docsBase}#fee-market-and-block-behavior`,
    confidence: 91,
  },
  {
    id: "ARC008",
    severity: "high",
    title: "USDC parsed with 18 ERC-20 decimals",
    extensions: ["ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["TypeScript", "JavaScript"],
    pattern: /\b(?:parseUnits\s*\([^\n,]+,\s*18\s*\)|parseEther\s*\()/gi,
    context: /\bUSDC\b/i,
    arcReason: "The Arc ERC-20 USDC interface uses 6 decimals even though native gas accounting uses 18.",
    impact: "An ERC-20 amount can be constructed 1e12 times too large, causing a revert or a dangerous approval request.",
    repair: "Use parseUnits(amount, 6) for ERC-20 USDC and keep 18 decimals only for explicit native-value accounting.",
    unsafe: "const amount = parseUnits(input, 18); // USDC",
    safe: "const amount = parseUnits(input, 6); // ERC-20 USDC",
    docs: `${docsBase}#usdc-as-the-native-gas-token`,
    confidence: 92,
  },
  {
    id: "ARC009",
    severity: "medium",
    title: "Timestamp used as the primary block ordering key",
    extensions: ["ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["TypeScript", "JavaScript"],
    pattern: /\.sort\s*\(\s*\([^)]*\)\s*=>[^\n]*(?:blockTimestamp|timestamp)[^\n]*\)/gi,
    arcReason: "Multiple Arc blocks can share one timestamp, making timestamp-only ordering ambiguous.",
    impact: "An indexer can present events out of order or produce non-deterministic derived state.",
    repair: "Sort by blockNumber, then transactionIndex and logIndex where event-level ordering matters.",
    unsafe: "events.sort((a, b) => a.timestamp - b.timestamp);",
    safe: "events.sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex);",
    docs: `${docsBase}#fee-market-and-block-behavior`,
    confidence: 90,
  },
  {
    id: "ARC010",
    severity: "medium",
    title: "Ethereum gas symbol used for Arc",
    extensions: ["ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["TypeScript", "JavaScript"],
    pattern: /(?:nativeCurrency|gasToken)[\s\S]{0,160}?(?:symbol|name)\s*:\s*["'](?:ETH|Ether|Ethereum)["']/gi,
    context: /\bArc(?:_Testnet)?\b|chainId\s*:\s*5042002/i,
    arcReason: "Arc uses USDC, not ETH, as its native gas token.",
    impact: "Wallet prompts and onboarding can show the wrong asset and tell users to acquire ETH they do not need.",
    repair: "Set the Arc native currency label to USDC and keep the configured native precision explicit.",
    unsafe: "nativeCurrency: { name: \"Ether\", symbol: \"ETH\", decimals: 18 }",
    safe: "nativeCurrency: { name: \"USDC\", symbol: \"USDC\", decimals: 18 }",
    docs: `${docsBase}#usdc-as-the-native-gas-token`,
    confidence: 95,
  },
  {
    id: "ARC011",
    severity: "low",
    title: "Extra confirmations are unnecessary on Arc",
    extensions: ["ts", "tsx", "js", "jsx", "mjs", "cjs"],
    languages: ["TypeScript", "JavaScript"],
    pattern: /\.wait\s*\(\s*(?:[2-9]|[1-9]\d+)\s*\)/g,
    arcReason: "Arc transactions are final on inclusion, so Ethereum-style multi-confirmation waits do not add safety.",
    impact: "Users experience avoidable latency and automation waits longer than the settlement model requires.",
    repair: "Wait for one confirmation and trigger downstream work after the final receipt is available.",
    unsafe: "await transaction.wait(12);",
    safe: "await transaction.wait(1);",
    docs: `${docsBase}#fee-market-and-block-behavior`,
    confidence: 98,
  },
];

const supportedExtensions = new Set(["sol", "ts", "tsx", "js", "jsx", "mjs", "cjs"]);
const codeInput = document.querySelector("#code-input");
const activeFileSelect = document.querySelector("#active-file-select");
const codeLanguage = document.querySelector("#code-language");
const scanButton = document.querySelector("#scan-button");
const clearButton = document.querySelector("#clear-code");
const loadSampleButton = document.querySelector("#load-sample");
const fileUpload = document.querySelector("#file-upload");
const folderUpload = document.querySelector("#folder-upload");
const repoUrl = document.querySelector("#repo-url");
const loadRepoButton = document.querySelector("#load-repo");
const scanSummary = document.querySelector("#scan-summary");
const resultsList = document.querySelector("#results-list");
const resultsProgress = document.querySelector("#results-progress");
const resultCount = document.querySelector("#result-count");
const exportJson = document.querySelector("#export-json");
const exportMarkdown = document.querySelector("#export-markdown");
const ruleGrid = document.querySelector("#rule-grid");
const ruleSearch = document.querySelector("#rule-search");
const ruleEmpty = document.querySelector("#rule-empty");

let loadedFiles = [];
let activeFileIndex = 0;
let lastReport = null;
let activeSeverity = "all";

function extensionOf(name) {
  return name.split(".").pop().toLowerCase();
}

function detectedLanguage(file) {
  if (file.languageOverride) return file.languageOverride;
  return extensionOf(file.name) === "sol" ? "sol" : "ts";
}

function saveActiveSource() {
  if (!loadedFiles[activeFileIndex]) return;
  loadedFiles[activeFileIndex].source = codeInput.value;
  loadedFiles[activeFileIndex].languageOverride = codeLanguage.value;
}

function setFiles(files) {
  loadedFiles = files;
  activeFileIndex = 0;
  activeFileSelect.replaceChildren();
  files.forEach((file, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = file.name;
    activeFileSelect.append(option);
  });
  syncActiveFile();
}

function syncActiveFile() {
  const file = loadedFiles[activeFileIndex];
  codeInput.value = file?.source ?? "";
  activeFileSelect.value = String(activeFileIndex);
  codeLanguage.value = file ? detectedLanguage(file) : "sol";
  updateScanSummary();
}

function updateScanSummary() {
  saveActiveSource();
  const lineCount = loadedFiles.reduce((total, file) => total + file.source.split(/\r?\n/).length, 0);
  scanSummary.textContent = `${loadedFiles.length} file${loadedFiles.length === 1 ? "" : "s"} · ${lineCount} line${lineCount === 1 ? "" : "s"}`;
}

function loadRiskySample(message = "Run the agent to inspect this intentionally risky Arc contract.") {
  setFiles([{ name: "PaymentVault.sol", source: sampleCode, languageOverride: "sol" }]);
  setResultsState("empty", "Risky sample ready", message);
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function setResultsState(type, title, message) {
  resultsList.replaceChildren();
  const card = makeElement("div", `state-card ${type}`);
  const icons = { empty: "⌁", scanning: "◌", error: "!", success: "✓" };
  card.append(makeElement("span", "state-icon", icons[type]), makeElement("strong", "", title), makeElement("p", "", message));
  resultsList.append(card);
  const labels = { empty: "Ready", scanning: "Scanning", error: "Error", success: "Clean" };
  resultCount.textContent = labels[type];
  resultsList.setAttribute("aria-busy", String(type === "scanning"));
  resultsProgress.classList.toggle("is-scanning", type === "scanning");
}

function lineFromOffset(source, offset) {
  return source.slice(0, offset).split("\n").length;
}

function ruleAppliesToFile(rule, file) {
  const language = detectedLanguage(file);
  const allowed = language === "sol" ? ["sol"] : ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
  return rule.extensions.some((extension) => allowed.includes(extension)) && (!rule.context || rule.context.test(file.source));
}

async function scanAll() {
  saveActiveSource();
  if (!loadedFiles.length || loadedFiles.every((file) => !file.source.trim())) {
    setResultsState("error", "Nothing to scan", "Paste code, upload files, load a folder, or open a public GitHub repository first.");
    return;
  }

  scanButton.disabled = true;
  exportJson.disabled = true;
  exportMarkdown.disabled = true;
  setResultsState("scanning", "ArcPort Agent is reasoning", "Applying source-level checks and mapping matches to Arc-specific behavior.");
  await delay(110);
  const findings = [];

  for (let fileIndex = 0; fileIndex < loadedFiles.length; fileIndex += 1) {
    const file = loadedFiles[fileIndex];
    for (const rule of rules) {
      if (!ruleAppliesToFile(rule, file)) continue;
      rule.pattern.lastIndex = 0;
      for (const match of file.source.matchAll(rule.pattern)) {
        findings.push({
          ...rule,
          file: file.name,
          line: lineFromOffset(file.source, match.index ?? 0),
          matchedText: match[0],
        });
      }
    }
    if (fileIndex > 0 && fileIndex % 8 === 0) await delay(0);
  }

  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => rank[b.severity] - rank[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  lastReport = {
    tool: "ArcPort Guard browser agent",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    analysis: "Conservative static compatibility analysis",
    filesScanned: loadedFiles.length,
    findings: findings.map(({ pattern, context, extensions, ...finding }) => finding),
  };
  renderFindings(findings);
  resultCount.textContent = findings.length ? `${findings.length} found` : "Clean";
  resultsProgress.classList.remove("is-scanning");
  resultsList.setAttribute("aria-busy", "false");
  exportJson.disabled = false;
  exportMarkdown.disabled = false;
  scanButton.disabled = false;
}

function findingSection(label, text, className = "") {
  const section = makeElement("div", `finding-section ${className}`.trim());
  section.append(makeElement("strong", "", label), makeElement("p", "", text));
  return section;
}

function renderFindings(findings) {
  resultsList.replaceChildren();
  if (!findings.length) {
    setResultsState("success", "No browser-check risks found", "The analyzed source passed all applicable browser rules. Run the full CLI and a security audit before deployment.");
    return;
  }

  for (const finding of findings) {
    const card = makeElement("article", `finding-card ${finding.severity}`);
    const head = makeElement("div", "finding-head");
    const meta = makeElement("div", "finding-meta");
    meta.append(
      makeElement("span", "finding-severity", `${finding.severity.toUpperCase()} · ${finding.id}`),
      makeElement("span", "finding-location", `${finding.file}:${finding.line}`),
    );
    head.append(meta, makeElement("h3", "", finding.title));
    const arcReason = findingSection("Why this matters on Arc", finding.arcReason);
    const impact = findingSection("Possible impact", finding.impact, "finding-impact");
    const repair = findingSection("Suggested repair", finding.repair, "finding-repair");
    const code = makeElement("pre", "finding-code");
    code.textContent = finding.safe;
    repair.append(code);
    const confidence = makeElement("div", "confidence-row");
    const confidenceTrack = makeElement("span", "confidence-track");
    const confidenceValue = makeElement("i");
    confidenceValue.style.width = `${finding.confidence}%`;
    confidenceTrack.append(confidenceValue);
    confidence.append(makeElement("span", "", "Confidence"), confidenceTrack, makeElement("b", "", `${finding.confidence}%`));
    repair.append(confidence);

    const actions = makeElement("div", "finding-actions");
    const copyFix = makeElement("button", "", "Copy fix");
    copyFix.type = "button";
    copyFix.addEventListener("click", async () => {
      const copied = await copyText(`${finding.repair}\n\nArc-safe example:\n${finding.safe}`);
      copyFix.textContent = copied ? "Fix copied" : "Copy failed";
      window.setTimeout(() => { copyFix.textContent = "Copy fix"; }, 1400);
    });
    const patchButton = makeElement("button", "", "Generate patch · Soon");
    patchButton.type = "button";
    patchButton.disabled = true;
    patchButton.title = "AI-generated patches are planned for v0.2";
    const docs = makeElement("a", "", "Official Arc docs ↗");
    docs.href = finding.docs;
    docs.target = "_blank";
    docs.rel = "noreferrer";
    actions.append(copyFix, patchButton, docs);
    card.append(head, arcReason, impact, repair, actions);
    resultsList.append(card);
  }
}

async function loadSelectedFiles(fileList) {
  const accepted = [...fileList]
    .filter((file) => supportedExtensions.has(extensionOf(file.name)))
    .slice(0, 100);
  const totalBytes = accepted.reduce((sum, file) => sum + file.size, 0);
  if (!accepted.length) {
    setResultsState("error", "No supported source files", "Choose Solidity, TypeScript, or JavaScript files.");
    return;
  }
  if (totalBytes > 5_000_000) {
    setResultsState("error", "Selection is too large", "Keep browser analysis under 5 MB so the page remains responsive.");
    return;
  }
  setResultsState("scanning", "Opening local files", "Reading source directly in your browser. Nothing is being uploaded.");
  const files = await Promise.all(accepted.map(async (file) => ({
    name: file.webkitRelativePath || file.name,
    source: await file.text(),
    languageOverride: extensionOf(file.name) === "sol" ? "sol" : "ts",
  })));
  setFiles(files);
  setResultsState("empty", `${files.length} file${files.length === 1 ? "" : "s"} loaded`, "Review the source or run the ArcPort Agent scan.");
}

function parseGitHubRepository(value) {
  try {
    const url = new URL(value.trim());
    if (url.hostname !== "github.com") return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1].replace(/\.git$/i, "") };
  } catch {
    return null;
  }
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (response.status === 403) throw new Error("GitHub rate limit reached. Wait a few minutes or upload the repository folder instead.");
  if (response.status === 404) throw new Error("Public repository not found. Check the URL and repository visibility.");
  if (!response.ok) throw new Error(`GitHub returned HTTP ${response.status}.`);
  return response.json();
}

async function loadPublicRepository() {
  const repository = parseGitHubRepository(repoUrl.value);
  if (!repository) {
    setResultsState("error", "Invalid GitHub URL", "Enter a public repository URL such as https://github.com/owner/repository.");
    repoUrl.focus();
    return;
  }

  loadRepoButton.disabled = true;
  setResultsState("scanning", "Loading public repository", "Downloading supported source files to this browser for local analysis.");
  try {
    const repo = await fetchJson(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repo)}`);
    const branch = repo.default_branch;
    const tree = await fetchJson(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    if (tree.truncated) throw new Error("This repository is too large for the browser loader. Upload a smaller folder instead.");
    const candidates = tree.tree
      .filter((entry) => entry.type === "blob" && supportedExtensions.has(extensionOf(entry.path)) && (entry.size ?? 0) <= 300_000)
      .slice(0, 100);
    if (!candidates.length) throw new Error("No supported Solidity, TypeScript, or JavaScript files were found.");
    const totalBytes = candidates.reduce((sum, entry) => sum + (entry.size ?? 0), 0);
    if (totalBytes > 5_000_000) throw new Error("The supported source files exceed the 5 MB browser limit. Upload a smaller folder instead.");

    const files = [];
    for (let index = 0; index < candidates.length; index += 8) {
      const batch = candidates.slice(index, index + 8);
      const loaded = await Promise.all(batch.map(async (entry) => {
        const path = entry.path.split("/").map(encodeURIComponent).join("/");
        const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repo)}/${encodeURIComponent(branch)}/${path}`;
        const response = await fetch(rawUrl);
        if (!response.ok) throw new Error(`Could not download ${entry.path}.`);
        return { name: entry.path, source: await response.text(), languageOverride: extensionOf(entry.path) === "sol" ? "sol" : "ts" };
      }));
      files.push(...loaded);
      resultCount.textContent = `${files.length}/${candidates.length}`;
    }
    setFiles(files);
    setResultsState("empty", `${repository.owner}/${repository.repo} loaded`, `${files.length} supported public source files are ready for local analysis.`);
  } catch (error) {
    setResultsState("error", "Repository could not be loaded", error instanceof Error ? error.message : "Unexpected GitHub error.");
  } finally {
    loadRepoButton.disabled = false;
  }
}

function reportAsMarkdown(report) {
  const lines = [
    "# ArcPort Guard report",
    "",
    `Scanned ${report.filesScanned} file(s). Found ${report.findings.length} compatibility issue(s).`,
    "",
    "> Conservative static compatibility analysis. This report does not replace a smart-contract security audit.",
    "",
  ];
  for (const finding of report.findings) {
    lines.push(
      `## ${finding.severity.toUpperCase()} ${finding.id}: ${finding.title}`,
      "",
      `- Location: \`${finding.file}:${finding.line}\``,
      `- Why it matters on Arc: ${finding.arcReason}`,
      `- Possible impact: ${finding.impact}`,
      `- Suggested repair: ${finding.repair}`,
      `- Confidence: ${finding.confidence}%`,
      `- Documentation: ${finding.docs}`,
      "",
      "```",
      finding.safe,
      "```",
      "",
    );
  }
  if (!report.findings.length) lines.push("No browser-check risks found. Run the full CLI before deployment.");
  return lines.join("\n");
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
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function renderRuleExplorer() {
  const query = ruleSearch.value.trim().toLowerCase();
  const filtered = rules.filter((rule) => {
    const matchesSeverity = activeSeverity === "all" || rule.severity === activeSeverity;
    const searchable = `${rule.id} ${rule.title} ${rule.severity} ${rule.languages.join(" ")} ${rule.arcReason} ${rule.impact}`.toLowerCase();
    return matchesSeverity && searchable.includes(query);
  });
  ruleGrid.replaceChildren();
  ruleEmpty.hidden = filtered.length > 0;

  for (const rule of filtered) {
    const card = makeElement("details", "rule-card");
    const summary = document.createElement("summary");
    summary.append(makeElement("span", "rule-id", rule.id));
    const titleWrap = makeElement("div");
    titleWrap.append(makeElement("strong", "", rule.title), makeElement("span", `severity-pill ${rule.severity}`, rule.severity));
    summary.append(titleWrap);
    const body = makeElement("div", "rule-body");
    const languages = makeElement("div", "rule-languages");
    rule.languages.forEach((language) => languages.append(makeElement("span", "", language)));
    const examples = makeElement("div", "rule-example-grid");
    const unsafe = makeElement("div", "rule-example");
    unsafe.append(makeElement("span", "", "UNSAFE"), makeElement("code", "", rule.unsafe));
    const safe = makeElement("div", "rule-example safe");
    safe.append(makeElement("span", "", "ARC-SAFE ALTERNATIVE"), makeElement("code", "", rule.safe));
    examples.append(unsafe, safe);
    const docs = makeElement("a", "rule-doc-link", "Read official Arc documentation ↗");
    docs.href = rule.docs;
    docs.target = "_blank";
    docs.rel = "noreferrer";
    body.append(languages, makeElement("p", "", rule.arcReason), examples, docs);
    card.append(summary, body);
    ruleGrid.append(card);
  }
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    const helper = document.createElement("textarea");
    helper.value = value;
    helper.style.position = "fixed";
    helper.style.opacity = "0";
    document.body.append(helper);
    helper.select();
    const copied = document.execCommand("copy");
    helper.remove();
    return copied;
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

activeFileSelect.addEventListener("change", () => {
  saveActiveSource();
  activeFileIndex = Number(activeFileSelect.value);
  syncActiveFile();
});
codeLanguage.addEventListener("change", () => {
  if (loadedFiles[activeFileIndex]) loadedFiles[activeFileIndex].languageOverride = codeLanguage.value;
});
codeInput.addEventListener("input", updateScanSummary);
codeInput.addEventListener("keydown", (event) => {
  if (event.key !== "Tab") return;
  event.preventDefault();
  codeInput.setRangeText("    ", codeInput.selectionStart, codeInput.selectionEnd, "end");
  updateScanSummary();
});
clearButton.addEventListener("click", () => {
  setFiles([{ name: "PastedCode.sol", source: "", languageOverride: "sol" }]);
  setResultsState("empty", "Editor cleared", "Choose Solidity or TypeScript, paste source code, then run the agent scan.");
  codeInput.focus();
});
loadSampleButton.addEventListener("click", () => loadRiskySample("The risky Solidity sample has been restored and is ready to scan."));
fileUpload.addEventListener("change", async () => {
  await loadSelectedFiles(fileUpload.files);
  fileUpload.value = "";
});
folderUpload.addEventListener("change", async () => {
  await loadSelectedFiles(folderUpload.files);
  folderUpload.value = "";
});
document.querySelectorAll("label.source-button[role='button']").forEach((label) => {
  label.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    document.querySelector(`#${label.htmlFor}`).click();
  });
});
loadRepoButton.addEventListener("click", loadPublicRepository);
repoUrl.addEventListener("keydown", (event) => {
  if (event.key === "Enter") loadPublicRepository();
});
scanButton.addEventListener("click", scanAll);
exportJson.addEventListener("click", () => downloadReport("json"));
exportMarkdown.addEventListener("click", () => downloadReport("markdown"));
ruleSearch.addEventListener("input", renderRuleExplorer);
document.querySelector("#rule-filters").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-severity]");
  if (!button) return;
  activeSeverity = button.dataset.severity;
  document.querySelectorAll("#rule-filters button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
  renderRuleExplorer();
});

const installCommand = document.querySelector("#install-command");
for (const tab of document.querySelectorAll(".install-tabs button")) {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".install-tabs button").forEach((item) => item.setAttribute("aria-selected", "false"));
    tab.setAttribute("aria-selected", "true");
    installCommand.textContent = tab.dataset.command;
  });
}
document.querySelector("#copy-command").addEventListener("click", async (event) => {
  const copied = await copyText(installCommand.textContent);
  event.currentTarget.textContent = copied ? "Copied" : "Copy failed";
  window.setTimeout(() => { event.currentTarget.textContent = "Copy"; }, 1400);
});

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const demoSteps = [...document.querySelectorAll("[data-demo-step]")];
const demoProgress = document.querySelector("#terminal-progress-bar");
const restartDemo = document.querySelector("#restart-demo");
let demoTimers = [];

function stopTerminalDemo() {
  demoTimers.forEach((timer) => window.clearTimeout(timer));
  demoTimers = [];
}

function runTerminalDemo() {
  stopTerminalDemo();
  demoSteps.forEach((step) => step.classList.add("demo-hidden"));
  demoProgress.style.width = "0";
  const timings = [300, 800, 1500, 2250, 2950];
  demoSteps.forEach((step, index) => {
    demoTimers.push(window.setTimeout(() => {
      step.classList.remove("demo-hidden");
      demoProgress.style.width = `${Math.min(100, (index + 1) * 22)}%`;
    }, timings[index]));
  });
  demoTimers.push(window.setTimeout(runTerminalDemo, 7800));
}

if (prefersReducedMotion) {
  demoSteps.forEach((step) => step.classList.remove("demo-hidden"));
  demoProgress.style.width = "100%";
  restartDemo.disabled = true;
} else {
  runTerminalDemo();
  restartDemo.addEventListener("click", runTerminalDemo);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopTerminalDemo();
    else runTerminalDemo();
  });
  const observer = new IntersectionObserver((entries, currentObserver) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-visible");
      currentObserver.unobserve(entry.target);
    });
  }, { threshold: 0.1 });
  document.querySelectorAll(".flow-node, .difference-grid article, .tool-grid article, .roadmap-list li").forEach((element) => {
    element.classList.add("reveal");
    observer.observe(element);
  });
}

loadRiskySample();
renderRuleExplorer();
