# Review, round 7

- Date: 2026-10-30
- Scope: review of the round 7 changes (merges of `collectors-4`, `deploy-env` and `web-removing`), at commit b8a29c1
- Status: R7-01 and R7-02 fixed in round 8 by the integrator, verified as fixed by the [round 8 verification](2026-10-30-verification-round-8.md)

| Finding | Fixed by | Commits | Test |
| --- | --- | --- | --- |
| R7-01 | integrator | 58e72bd | `scripts/test/run.test.ts` (R7-01: `unsafeVars` names `NODE_DEBUG` and `NODE_DEBUG_NATIVE`; a child Node process runs the real `processRunner({credentials: 'token'})` with `NODE_DEBUG=child_process` and `*`, and its stderr never holds the token); `scripts/test/deploy.test.ts` (R7-01: refused in a dry run, before any config is read). `processRunner` itself starts nothing while an `UNSAFE_VARS` entry is set |
| R7-02 | integrator | 58e72bd | `scripts/test/run.test.ts` and `deploy.test.ts` (R7-02: `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`, `DYLD_FALLBACK_FRAMEWORK_PATH`, `DYLD_VERSIONED_LIBRARY_PATH`, `DYLD_VERSIONED_FRAMEWORK_PATH` and `NODE_COMPILE_CACHE`, on Linux, macOS and Windows) |

## Summary

Read-only review. No tracked file was changed. The scripts suite passed (158 tests).

Checked without a new finding:

- **Decision 0005.** A truncated class is never `complete`: the sweep step skips it and `graph.sweep` refuses it again, and rules that require it are `not_evaluated`. No other collector emits `tunnel` or `tunnel_hostname` nodes. Truncated reasons are size-limited and reach the SPA only through `<Text>` and MCP only inside `untrustedBlock`; core does not log them. The byte budget uses the same `canonicalJson` and `TextEncoder` as the write path.
- **Proxy printing.** 27 proxy values, including credentials without a scheme and `#`, `/` or `?` in the password, never printed the password.
- **`assets.directory`.** Paths and links that leave the app directory are refused, matching how Wrangler resolves the path.
- **The `removing` state.** Untrusted text stays escaped, admin routes are checked on the server, and the MCP server has no admin tools.

## New findings

### R7-01 [low] NODE_DEBUG=child_process makes the deploy print CLOUDFLARE_API_TOKEN in clear text; the deploy does not refuse it

Location: `scripts/lib/run.ts:249`

**Scenario**

An operator or CI job runs a real deploy with NODE_DEBUG=child_process set, for example to debug a Wrangler spawn failure. NODE_DEBUG is a documented Node debugging aid and is not in UNSAFE_VARS, so step 1 lets the deploy run. Node reads NODE_DEBUG at startup. On every Wrangler spawn its child_process debug log writes the spawn options to the deploy process's own stderr, including `env` and `envPairs`, which hold CLOUDFLARE_API_TOKEN (wranglerEnv adds the token for credentials 'token'). Only the children's stdout and stderr pass through `redact`; Node's own debug output goes straight to the terminal or CI log, so the token shape check does not apply. The token appears twice per Wrangler call. That breaks the rule that tokens never appear in logs, and the operator guide's promise that the script 'never prints the token'. wranglerEnv keeps NODE_DEBUG away from Wrangler, but the variable acts on the deploy process itself. A dry run passes no token to Wrangler, so only real deploys leak.

**Fix**

Add NODE_DEBUG (and NODE_DEBUG_NATIVE) to UNSAFE_VARS and refuse any non-empty value, like NODE_OPTIONS. Node reads it at startup, so deleting it from process.env later does not help. List it in step 1 of the operator guide and in its troubleshooting table. Add a unit test that unsafeVars names NODE_DEBUG. Add a test that runs processRunner({credentials:'token'}) in a child Node process with NODE_DEBUG=child_process and checks that the token never reaches that child's stderr.

**How it was verified**

In /tmp/review-7/copy (a copy of the repository without node_modules and .git), each apps/*/node_modules/.bin/wrangler was replaced by a shell stub, and the broker's store_id placeholder was set to a hex value. I ran: `env -u NODE_OPTIONS NODE_DEBUG=child_process CLOUDFLARE_API_TOKEN=cfat_REVIEW7SECRETabcdefghijklmnopqrstuvwxyz0123 CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef node scripts/deploy.ts`. It passed step 1 and printed the plan. On its first Wrangler call (`d1 list`) it wrote `CLOUDFLARE_API_TOKEN: 'cfat_REVIEW7SECRET...'` and `CLOUDFLARE_API_TOKEN=cfat_REVIEW7SECRET...` to stderr: 2 matching lines in /tmp/review-7/nodedebug-out.txt. /tmp/review-7/nodedebug.ts, which calls the real processRunner({credentials:'token'}) on a stub wrangler, printed the full 44-character token the same way. /tmp/review-7/unsafe.ts shows that unsafeVars({NODE_DEBUG:'child_process'}) returns [].

### R7-02 [low] LD_LIBRARY_PATH loads code into the deploy process, which holds the token, and is not refused (it is like LD_PRELOAD, which is refused)

Location: `scripts/lib/run.ts:249`

**Scenario**

UNSAFE_VARS refuses LD_PRELOAD, LD_AUDIT and DYLD_INSERT_LIBRARIES because they load code into the deploy script, which holds the token, before the script could drop them. LD_LIBRARY_PATH does the same. The dynamic loader searches it first for Node's own dependencies (libdl.so.2, libstdc++.so.6, libgcc_s.so.1, libm.so.6, libpthread.so.0 for Node 22.22.0). A library under one of those names in a directory on LD_LIBRARY_PATH runs its constructor inside `node scripts/deploy.ts`, with CLOUDFLARE_API_TOKEN in the environment. The same library also loads into every pnpm build, which gets the full environment. Only Wrangler itself is spared, because wranglerEnv drops the variable. The deploy does not refuse it, and scripts/test/run.test.ts lists LD_LIBRARY_PATH only as a variable to keep from Wrangler. The macOS DYLD_LIBRARY_PATH, DYLD_FALLBACK_LIBRARY_PATH and DYLD_FRAMEWORK_PATH work the same way for an unhardened node, such as Homebrew's; I could not test this without a Mac.

**Fix**

Add LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, DYLD_FALLBACK_LIBRARY_PATH, DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_FRAMEWORK_PATH to UNSAFE_VARS, using the same message as LD_PRELOAD. Also consider NODE_COMPILE_CACHE, which makes Node load cached compiled code from a directory. Extend the unsafeVars test and step 1 and the troubleshooting table of the operator guide.

**How it was verified**

Built /tmp/review-7/ldlib/libdl.so.2 from /tmp/review-7/ldlib/fake.c, using a version script that defines GLIBC_2.2.5, the only version Node 22.22.0 needs from libdl.so.2 (readelf -V); libc 2.39 still provides the real dl* symbols. Its constructor prints the pid and the length of CLOUDFLARE_API_TOKEN. In /tmp/review-7/copy I ran: `env -u NODE_OPTIONS LD_LIBRARY_PATH=/tmp/review-7/ldlib CLOUDFLARE_API_TOKEN=cfat_REVIEW7SECRET... CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef node scripts/deploy.ts`. It printed `[ld-library-path] code loaded into pid 18246; CLOUDFLARE_API_TOKEN length 48` before any output of the deploy, then went on to 'Configs: ... service bindings match' and the plan; step 1 did not refuse it. /tmp/review-7/unsafe.ts shows that unsafeVars({LD_LIBRARY_PATH, NODE_DEBUG, DYLD_LIBRARY_PATH, DYLD_FALLBACK_LIBRARY_PATH, NODE_COMPILE_CACHE, LD_PRELOAD}, 'linux' and 'darwin') returns only ['LD_PRELOAD'].
