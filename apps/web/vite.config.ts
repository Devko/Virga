import { defineConfig } from "vite";

// The SPA under spa/, built into the Worker's static assets (wrangler.jsonc).
export default defineConfig({
  root: "spa",
  publicDir: "public",
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
