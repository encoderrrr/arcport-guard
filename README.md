# ArcPort Guard

ArcPort Guard is an open-source Arc deployment compatibility agent. Its zero-dependency CLI and local-only browser scanner find Arc-specific risks in Solidity and JavaScript/TypeScript projects before deployment.

**[Try the browser agent](https://arc-brown-delta.vercel.app/)** — paste code, upload files or a folder, or load a public GitHub repository. Analysis stays in the browser and reports export as JSON or Markdown.

Arc is EVM compatible, but its native USDC model and protocol behavior differ from Ethereum in important ways. Standard local EVM simulators cannot reproduce every Arc-specific behavior, so a contract can pass locally and still fail or behave incorrectly on Arc.

## Quick start

Node.js 20 or newer is required.

```bash
npx github:encoderrrr/arcport-guard scan ./contracts
```

The command exits with code `1` when it finds a high or critical issue, making it suitable for CI.

## Examples

Human-readable report:

```bash
arcport scan . --fail-on high
```

JSON for another tool or CI annotation step:

```bash
arcport scan . --format json --min-severity medium
```

Custom configuration:

```bash
arcport scan . --config arcport.config.json
```

```json
{
  "ignore": ["vendor", "generated"],
  "disabledRules": ["ARC011"]
}
```

Suppress one intentional finding at the source:

```solidity
// arcport-ignore-next-line ARC002
return uint256(block.prevrandao);
```

## Included rules

| Rule | Severity | Check |
| --- | --- | --- |
| ARC001 | High | Native USDC and ERC-20 USDC raw balance comparison |
| ARC002 | Critical | `PREVRANDAO` or `block.difficulty` used as randomness |
| ARC003 | High | EIP-4788 beacon-root dependency |
| ARC004 | High | EIP-4844/blob transaction dependency |
| ARC005 | High | `SELFDESTRUCT` with Arc-specific value behavior |
| ARC006 | High | Native-value transfer to the zero address |
| ARC007 | Medium | Strict block timestamp ordering assumption |
| ARC008 | High | ERC-20 USDC parsed with 18 decimals |
| ARC009 | Medium | Timestamp-only block ordering in an indexer |
| ARC010 | Medium | ETH configured as Arc's native gas token |
| ARC011 | Low | Waiting for unnecessary extra confirmations |

Every finding includes a location, explanation, suggested fix, and link to the relevant Arc documentation.

## GitHub Action

```yaml
- uses: encoderrrr/arcport-guard@v0.1.0
  with:
    path: contracts
    fail-on: high
```

The browser playground is for fast feedback. The CLI remains the release gate because it scans whole projects, supports configuration and suppressions, and returns CI-ready exit codes.

## Current scope

Version 0.1 uses intentionally conservative static rules. It does not claim to prove contract safety. Dynamic Arc Testnet execution and framework integrations are planned for later releases.

## References

- [Arc EVM differences](https://docs.arc.io/arc/references/evm-differences)
- [Arc stablecoin-native model](https://docs.arc.io/arc/concepts/stablecoin-native-model)
- [Arc deterministic finality](https://docs.arc.io/arc/concepts/deterministic-finality)
