# CF-001: PLACEHOLDER. Phase 2 rule; nothing is created here yet.
#
# The phase 2 gate needs a seeded vulnerable Worker, "including the service
# binding variant" (implementation plan, phase 2 gate 1):
# - a public Worker version with a package that has an open critical or
#   known-exploited advisory, detected with at least medium confidence, and a
#   data store binding;
# - a variant where the public Worker reaches the store through one service
#   binding;
# - clean counterparts: the same Workers with a fixed package version, and
#   one behind Access.
#
# Not seeded yet because:
# - the collectors that read bundles, packages and advisories arrive in
#   phase 2, so nothing could check the case now;
# - `package_dependencies` on cloudflare_workers_script alone gives a package
#   low confidence (A-11). Medium needs the bundle or its source maps to show
#   the package, so the case is best built as a small Wrangler project with a
#   pinned vulnerable package, deployed by a script next to this
#   configuration.
# The package must never run with input from outside: like every Worker of
# the range, the seeded one answers with a fixed text. cases.yaml marks
# CF-001 as a placeholder without cases.
