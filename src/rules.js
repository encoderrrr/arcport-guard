export const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const DOCS = "https://docs.arc.io/arc/references/evm-differences";

export const rules = [
  {
    id: "ARC001",
    title: "Native USDC and ERC-20 USDC use different decimals",
    severity: "high",
    languages: ["solidity"],
    docs: DOCS + "#usdc-as-the-native-gas-token",
    message:
      "This file reads both address.balance (18 decimals) and USDC.balanceOf (6 decimals). They expose the same underlying balance with different precision, so raw values must not be compared or combined.",
    suggestion:
      "Normalize explicitly at the boundary. Convert native units and ERC-20 units into one named application unit before comparison or arithmetic.",
    detect(source) {
      return matches(
        source,
        /\bbalanceOf\s*\([^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\.balance\b|\.balance\b[^;{}]{0,160}?(?:===?|!==?|[+\-*/])[^;{}]{0,160}?\bbalanceOf\s*\(/g,
      );
    },
  },
  {
    id: "ARC002",
    title: "PREVRANDAO is always zero on Arc",
    severity: "critical",
    languages: ["solidity"],
    docs: DOCS + "#execution-and-opcode-differences",
    message:
      "Arc returns zero for PREVRANDAO. Using block.prevrandao or block.difficulty for randomness makes the result predictable.",
    suggestion: "Use a trusted oracle or a verifiable random function (VRF).",
    detect: (source) => matches(source, /\bblock\.(?:prevrandao|difficulty)\b|\bPREVRANDAO\b/g),
  },
  {
    id: "ARC003",
    title: "Beacon roots are unavailable on Arc",
    severity: "high",
    languages: ["solidity", "typescript", "javascript"],
    docs: DOCS + "#execution-and-opcode-differences",
    message:
      "Arc omits the EIP-4788 beacon-roots contract; reads return empty data. The parentBeaconBlockRoot field is not an Ethereum beacon root on Arc.",
    suggestion: "Do not use beacon roots for proofs or randomness on Arc. Use an Arc-compatible oracle.",
    detect: (source) => matches(source, /\bparentBeaconBlockRoot\b|\bbeacon[-_ ]?roots?\b/gi),
  },
  {
    id: "ARC004",
    title: "Blob transactions are unsupported",
    severity: "high",
    languages: ["solidity", "typescript", "javascript"],
    docs: DOCS + "#execution-and-opcode-differences",
    message:
      "Arc rejects EIP-4844 type-3 blob transactions. BLOBHASH returns zero and BLOBBASEFEE returns one.",
    suggestion: "Use calldata and a supported transaction type when submitting to Arc.",
    detect: (source) => matches(source, /\bBLOBHASH\b|\bBLOBBASEFEE\b|\beip[-_]?4844\b|\btype\s*:\s*["'](?:0x)?3["']|\bblobs?\s*:/gi),
  },
  {
    id: "ARC005",
    title: "SELFDESTRUCT has Arc-specific value rules",
    severity: "high",
    languages: ["solidity"],
    docs: DOCS + "#selfdestruct",
    message:
      "On Arc, SELFDESTRUCT moves the contract's underlying USDC balance and can revert for zero, self, blocklisted, or already-destroyed beneficiaries.",
    suggestion:
      "Remove SELFDESTRUCT where possible. Otherwise test every beneficiary and balance path against Arc Testnet.",
    detect: (source) => matches(source, /\bselfdestruct\s*\(/gi),
  },
  {
    id: "ARC006",
    title: "Value transfer to the zero address reverts",
    severity: "high",
    languages: ["solidity"],
    docs: DOCS + "#value-transfer-rules",
    message: "Arc forbids burning native USDC. A non-zero value transfer to address(0) reverts.",
    suggestion: "Reject the zero address before a native-value call or send funds to an explicit recovery address.",
    detect: (source) => matches(source, /address\s*\(\s*0\s*\)\s*\.(?:call|transfer|send)\b|payable\s*\(\s*address\s*\(\s*0\s*\)\s*\)/g),
  },
  {
    id: "ARC007",
    title: "Block timestamps are not strictly increasing",
    severity: "medium",
    languages: ["solidity"],
    docs: DOCS + "#fee-market-and-block-behavior",
    message:
      "Arc has sub-second blocks but one-second timestamp precision, so consecutive blocks can share the same block.timestamp.",
    suggestion: "Use block.number for ordering. Use timestamps only for elapsed-time checks that allow equality.",
    detect: (source) => matches(source, /(?:require\s*\(|if\s*\()[^\n;{}]*block\.timestamp\s*>\s*[A-Za-z_$][\w$]*(?:Timestamp|Time|At)\b/g),
  },
  {
    id: "ARC008",
    title: "USDC parsed with 18 ERC-20 decimals",
    severity: "high",
    languages: ["typescript", "javascript"],
    docs: DOCS + "#usdc-as-the-native-gas-token",
    message:
      "The Arc ERC-20 USDC interface uses 6 decimals. parseUnits(..., 18) or parseEther used in a USDC operation is likely 1e12 times too large.",
    suggestion: "Use parseUnits(amount, 6) for ERC-20 USDC. Use 18 decimals only for Arc native-value accounting.",
    detect(source) {
      const hits = [];
      const lines = source.split(/\r?\n/);
      for (let index = 0; index < lines.length; index += 1) {
        const context = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 3)).join("\n");
        if (/\bUSDC\b/i.test(context) && /\b(?:parseUnits\s*\([^\n,]+,\s*18\s*\)|parseEther\s*\()/i.test(lines[index])) {
          const column = Math.max(0, lines[index].search(/parseUnits|parseEther/i));
          hits.push(offsetFromLineColumn(lines, index, column));
        }
      }
      return hits;
    },
  },
  {
    id: "ARC009",
    title: "Timestamp used as the primary block ordering key",
    severity: "medium",
    languages: ["typescript", "javascript"],
    docs: DOCS + "#fee-market-and-block-behavior",
    message: "Multiple Arc blocks can have the same timestamp, making timestamp-only ordering ambiguous.",
    suggestion: "Order by blockNumber, then transactionIndex and logIndex where needed.",
    detect: (source) => matches(source, /\.sort\s*\(\s*\([^)]*\)\s*=>[^\n]*(?:blockTimestamp|timestamp)[^\n]*\)/gi),
  },
  {
    id: "ARC010",
    title: "Ethereum gas symbol used for Arc",
    severity: "medium",
    languages: ["typescript", "javascript"],
    docs: DOCS + "#usdc-as-the-native-gas-token",
    message: "Arc uses USDC, not ETH, as the native gas token.",
    suggestion: "Label Arc native balances and fees as USDC; do not ask users to acquire ETH for Arc gas.",
    detect(source) {
      if (!/\bArc(?:_Testnet)?\b|chainId\s*:\s*5042002/i.test(source)) return [];
      return matches(source, /(?:nativeCurrency|gasToken)[\s\S]{0,160}?(?:symbol|name)\s*:\s*["'](?:ETH|Ether|Ethereum)["']/gi);
    },
  },
  {
    id: "ARC011",
    title: "Extra confirmations are unnecessary on Arc",
    severity: "low",
    languages: ["typescript", "javascript"],
    docs: DOCS + "#fee-market-and-block-behavior",
    message: "Arc transactions are final on inclusion; waiting for multiple confirmations adds avoidable latency.",
    suggestion: "Use one confirmation and trigger downstream work immediately after the receipt is final.",
    detect: (source) => matches(source, /\.wait\s*\(\s*(?:[2-9]|[1-9]\d+)\s*\)/g),
  },
];

function matches(source, regex) {
  const hits = [];
  for (const match of source.matchAll(regex)) hits.push(match.index ?? 0);
  return hits;
}

function offsetFromLineColumn(lines, lineIndex, column) {
  let offset = 0;
  for (let index = 0; index < lineIndex; index += 1) offset += lines[index].length + 1;
  return offset + column;
}
