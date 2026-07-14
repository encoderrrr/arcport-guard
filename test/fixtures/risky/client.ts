import { parseEther } from "viem";

const chain = "Arc_Testnet";
const token = "USDC";
const amount = parseEther("1");

export async function settle(transaction: { wait(confirmations: number): Promise<void> }) {
  await transaction.wait(6);
  return { chain, token, amount };
}
