import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export async function loadConfig(configPath) {
  if (!configPath) return { ignore: [], disabledRules: new Set() };
  const absolutePath = resolve(configPath);
  const parsed = JSON.parse(await readFile(absolutePath, "utf8"));
  return {
    ignore: Array.isArray(parsed.ignore) ? parsed.ignore : [],
    disabledRules: new Set(Array.isArray(parsed.disabledRules) ? parsed.disabledRules : []),
  };
}
