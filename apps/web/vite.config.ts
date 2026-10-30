import { lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";

/**
 * Vite copies the public directory into the assets and follows symlinks while
 * it copies, so a link there would publish the file or directory it points
 * to, wherever that is. The build fails instead (R6-01).
 */
function plainPublicDir(): Plugin {
  let publicDir = "";
  return {
    name: "virga:plain-public-dir",
    apply: "build",
    configResolved(config) {
      publicDir = config.publicDir;
    },
    buildStart() {
      const links: string[] = [];
      const visit = (path: string) => {
        const stat = lstatSync(path, { throwIfNoEntry: false });
        if (stat?.isSymbolicLink()) links.push(path);
        else if (stat?.isDirectory()) for (const name of readdirSync(path)) visit(join(path, name));
      };
      if (publicDir !== "") visit(publicDir);
      if (links.length > 0) {
        throw new Error(
          links
            .sort()
            .map(
              (path) =>
                `${path}: the public directory holds a symlink, and Vite would copy what it points to into the assets. Replace it with the file`,
            )
            .join("\n"),
        );
      }
    },
  };
}

// The SPA under spa/, built into the Worker's static assets (wrangler.jsonc).
export default defineConfig({
  root: "spa",
  publicDir: "public",
  plugins: [plainPublicDir()],
  oxc: { jsx: { runtime: "automatic", importSource: "react" } },
  build: {
    outDir: "../dist/client",
    emptyOutDir: true,
    // No data: URIs (the CSP allows images and fonts from 'self' only) and no
    // injected polyfill code.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
});
