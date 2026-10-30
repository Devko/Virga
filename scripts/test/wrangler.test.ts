import { createHash } from "node:crypto";
import {
  appendFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  describeChanges,
  recordWrangler,
  recordWranglers,
  wranglerChanges,
} from "../lib/wrangler.ts";
import { type FakeWrangler, fakeWrangler, put } from "./helpers.ts";

const BIN = 'console.log("wrangler");\n';

let root = "";
let web = "";
let fake: FakeWrangler;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "virga-wrangler-")));
  web = join(root, "apps", "web");
  fake = fakeWrangler(root, [web], BIN);
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("recordWrangler", () => {
  it("R6-01: records the package's bin file and every file Node can load for Wrangler", () => {
    const install = recordWrangler(web);
    expect(install).toMatchObject({
      appDir: web,
      dir: fake.wrangler,
      bin: fake.bin,
      version: "4.151.0",
    });
    const files = [...install.files.keys()].filter((path) => !path.endsWith(sep));
    expect(files.sort()).toEqual(
      [
        join(fake.wrangler, "package.json"),
        fake.bin,
        join(fake.wrangler, "wrangler-dist", "cli.js"),
        // Dependencies as Node resolves them, with symlinks followed.
        join(fake.esbuild, "package.json"),
        join(fake.esbuild, "lib", "main.js"),
        join(fake.platform, "package.json"),
        join(fake.platform, "bin", "esbuild"),
        // The shim, which `npx wrangler` runs; not the other shims.
        join(web, "node_modules", ".bin", "wrangler"),
      ].sort(),
    );
    expect(install.files.get(fake.bin)).toBe(createHash("sha256").update(BIN).digest("hex"));
    // The node_modules directories a bare require from these packages searches.
    const store = join(root, "node_modules", ".pnpm");
    for (const dir of [
      join(fake.wrangler, "node_modules"),
      join(store, "wrangler@4.151.0", "node_modules"),
      join(store, "esbuild@0.28.2", "node_modules"),
      join(store, "node_modules"),
      join(root, "node_modules"),
    ]) {
      expect(install.files.has(`${dir}${sep}`), dir).toBe(true);
    }
  });

  it("R6-01: names a package planted where a require from Wrangler would find it", () => {
    const install = recordWrangler(web);
    // pnpm's hoisting directory, which Node searches from every package in the store.
    const hoisted = join(root, "node_modules", ".pnpm", "node_modules");
    put(join(hoisted, "bufferutil", "index.js"), "// planted\n");
    expect(wranglerChanges(install)).toEqual([`${hoisted}${sep}`]);
    rmSync(join(hoisted, "bufferutil"), { recursive: true });
    expect(wranglerChanges(install)).toEqual([]);
    put(join(hoisted, "@aws-sdk", "signature-v4-crt", "index.js"), "// planted\n");
    expect(wranglerChanges(install)).toEqual([`${hoisted}${sep}`]);
  });

  it("R6-01: finds nothing changed when nothing changed", () => {
    const install = recordWrangler(web);
    expect(wranglerChanges(install)).toEqual([]);
  });

  it("R6-01: names a changed bin file, wrangler-dist file, dependency and shim", () => {
    const install = recordWrangler(web);
    appendFileSync(fake.bin, 'require("child_process").exec("curl ...");\n');
    appendFileSync(join(fake.wrangler, "wrangler-dist", "cli.js"), "// planted\n");
    appendFileSync(join(fake.esbuild, "lib", "main.js"), "// planted\n");
    appendFileSync(join(fake.platform, "bin", "esbuild"), "planted");
    appendFileSync(join(web, "node_modules", ".bin", "wrangler"), "echo planted\n");
    expect(wranglerChanges(install)).toEqual(
      [
        fake.bin,
        join(fake.wrangler, "wrangler-dist", "cli.js"),
        join(fake.esbuild, "lib", "main.js"),
        join(fake.platform, "bin", "esbuild"),
        join(web, "node_modules", ".bin", "wrangler"),
      ].sort(),
    );
  });

  it("R6-01: names a file replaced by a symlink to the same bytes, which can change later", () => {
    const install = recordWrangler(web);
    const cli = join(fake.wrangler, "wrangler-dist", "cli.js");
    cpSync(cli, join(root, "cli.js"));
    rmSync(cli);
    symlinkSync(join(root, "cli.js"), cli);
    expect(wranglerChanges(install)).toEqual([cli]);
  });

  it("R6-01: reports a package that is no Wrangler any more", () => {
    const install = recordWrangler(web);
    writeFileSync(join(fake.wrangler, "package.json"), "{}");
    expect(wranglerChanges(install)).toEqual([
      `${join(web, "node_modules", "wrangler")} is not the wrangler package; run pnpm install first`,
    ]);
  });

  it("R6-01: names files added to or removed from the package", () => {
    const install = recordWrangler(web);
    put(join(fake.wrangler, "wrangler-dist", "extra.js"), "// planted\n");
    rmSync(join(fake.esbuild, "lib", "main.js"));
    expect(wranglerChanges(install)).toEqual([
      join(fake.esbuild, "lib", "main.js"),
      join(fake.wrangler, "wrangler-dist", "extra.js"),
    ]);
  });

  it("R6-01: names a dependency that now resolves to another package", () => {
    const install = recordWrangler(web);
    const evil = join(root, "evil", "esbuild");
    cpSync(fake.esbuild, evil, { recursive: true });
    const link = join(root, "node_modules", ".pnpm", "wrangler@4.151.0", "node_modules", "esbuild");
    rmSync(link);
    symlinkSync(evil, link);
    const changes = wranglerChanges(install);
    expect(changes).toContain(join(evil, "lib", "main.js"));
    expect(changes).toContain(join(fake.esbuild, "lib", "main.js"));
  });

  it("R6-01: names an optional dependency planted where Node would find it", () => {
    const install = recordWrangler(web);
    const planted = join(
      root,
      "node_modules",
      ".pnpm",
      "esbuild@0.28.2",
      "node_modules",
      "@esbuild",
      "darwin-arm64",
    );
    put(join(planted, "package.json"), "{}");
    const nodeModules = join(root, "node_modules", ".pnpm", "esbuild@0.28.2", "node_modules");
    expect(wranglerChanges(install)).toEqual([
      `${nodeModules}${sep}`,
      // Where the planted package's own requires would look.
      `${join(nodeModules, "@esbuild", "darwin-arm64", "node_modules")}${sep}`,
      join(planted, "package.json"),
      `${join(nodeModules, "@esbuild", "node_modules")}${sep}`,
    ]);
  });

  it("R6-01: names an app whose node_modules/wrangler now points to another package", () => {
    const install = recordWrangler(web);
    const copy = join(root, "copy", "wrangler");
    cpSync(fake.wrangler, copy, { recursive: true, verbatimSymlinks: true });
    rmSync(join(web, "node_modules", "wrangler"));
    symlinkSync(copy, join(web, "node_modules", "wrangler"));
    expect(wranglerChanges(install)).toContain(`${fake.wrangler} (now ${copy})`);
  });

  it("R6-01: refuses a missing Wrangler, another package, and a bin file outside the package", () => {
    mkdirSync(join(root, "apps", "core"));
    expect(() => recordWrangler(join(root, "apps", "core"))).toThrow(
      `${join(root, "apps", "core", "node_modules", "wrangler")} not found; run pnpm install first`,
    );
    put(
      join(fake.wrangler, "package.json"),
      JSON.stringify({ name: "wrangler", version: "4.151.0", bin: { wrangler: "../../x.js" } }),
    );
    put(join(fake.wrangler, "..", "..", "x.js"), BIN);
    expect(() => recordWrangler(web)).toThrow(
      /the wrangler bin file is missing or outside the package/,
    );
    put(join(fake.wrangler, "package.json"), JSON.stringify({ name: "wranglerx", version: "1" }));
    expect(() => recordWrangler(web)).toThrow(/is not the wrangler package/);
  });

  it("R6-01: records each app, sharing the hashes of a package they share", () => {
    const core = join(root, "apps", "core");
    mkdirSync(join(core, "node_modules", ".bin"), { recursive: true });
    symlinkSync(fake.wrangler, join(core, "node_modules", "wrangler"));
    const installs = recordWranglers([web, core]);
    expect(installs.get(core)?.dir).toBe(fake.wrangler);
    expect(installs.get(core)?.files.size).toBe((installs.get(web)?.files.size ?? 0) - 1);
  });
});

describe("describeChanges", () => {
  it("R6-01: names up to five changes and counts the rest", () => {
    expect(describeChanges(web, [])).toBeNull();
    const message = describeChanges(
      web,
      ["a", "b", "c", "d", "e", "f", "g"].map((f) => `/x/${f}`),
    );
    expect(message).toContain(
      `the Wrangler of ${web} changed after the deploy recorded it before the builds: /x/a, /x/b, /x/c, /x/d, /x/e and 2 more.`,
    );
  });
});
