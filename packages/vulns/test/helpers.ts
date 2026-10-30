import { readdirSync, readFileSync } from "node:fs";

const root = new URL("./fixtures/", import.meta.url);

/** A hand-written fixture file as text. */
export const fixture = (path: string): string => readFileSync(new URL(path, root), "utf8");

/** Every OSV fixture record as text, sorted by file name. */
export const osvFixtures = (): string[] =>
  readdirSync(new URL("osv/", root))
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => fixture(`osv/${name}`));
