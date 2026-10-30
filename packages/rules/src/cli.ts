// Usage: node packages/rules/src/cli.ts build|check
//   build  compiles rules/, runs all fixtures and writes the generated modules
//   check  does the same but fails if the generated modules are out of date
import { writeFileSync } from "node:fs";
import { checkGenerated } from "./generate.ts";

const mode = process.argv[2];
if (mode !== "build" && mode !== "check") {
  console.error("usage: cli.ts build|check");
  process.exit(2);
}

const { errors, files, rules, fixtures } = await checkGenerated();

if (errors.length > 0) {
  for (const error of errors) console.error(`error: ${error}`);
  process.exit(1);
}

let stale = false;
for (const file of files) {
  if (!file.stale) continue;
  if (mode === "check") {
    console.error(`error: ${file.name} is out of date; run pnpm rules:build`);
    stale = true;
  } else {
    writeFileSync(file.path, file.content);
  }
}
if (stale) process.exit(1);
console.log(`${rules} rule(s), ${fixtures} fixture(s) passed`);
