/** Access settings for tests; vitest.config.ts binds them as vars. */
export const TEST_ACCESS = {
  ACCESS_TEAM_DOMAIN: "https://virga-test.cloudflareaccess.com",
  ACCESS_AUD: "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2",
  ADMIN_EMAILS: " Admin@Example.com, ops@example.com ",
  REQUIRE_ACCESS_CONTEXT: "false",
} as const;

export const ADMIN = "admin@example.com";
export const VIEWER = "viewer@example.com";
export const ORIGIN = "https://virga.example.com";
