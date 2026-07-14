import { cp, mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";

const source = resolve("site");
const destination = resolve("dist");

await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });

console.log(`Built ArcPort Guard site at ${destination}`);
