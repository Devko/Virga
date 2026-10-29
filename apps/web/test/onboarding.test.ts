import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scrub } from "../src/api.ts";
import { ADMIN } from "./config.ts";
import { ACCOUNT } from "./fixtures.ts";
import { call, captureLogs, serveCerts, signer, tokenFor } from "./helpers.ts";
import { calls } from "./worker.ts";

// Fake tokens in the account API token format; never real credentials.
const GOOD = "cfat_TESTONLYgoodtoken0123456789abcdefABCDEF";
const REJECTED = "rejectTESTONLY0123456789abcdefABCDEF_token";
const THROWS = "throwTESTONLY0123456789abcdefABCDEF_token";

let admin: string;
let logs: ReturnType<typeof captureLogs>;

beforeEach(async () => {
  serveCerts(await signer());
  admin = await tokenFor(ADMIN);
  calls.length = 0;
  logs = captureLogs();
});
afterEach(() => {
  logs.restore();
  vi.restoreAllMocks();
});

const onboard = (body: unknown) => call("/api/accounts", { token: admin, body });

async function text(response: Response): Promise<string> {
  const body = await response.text();
  return `${response.status} ${[...response.headers].join(" ")} ${body}`;
}

describe("onboarding", () => {
  it("stores the token in the broker, then registers the account", async () => {
    const response = await onboard({
      accountId: ACCOUNT,
      token: GOOD,
      profile: "workload",
      name: "  Production ",
      cadenceHours: 12,
    });
    const raw = await text(response.clone());
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      account: expect.objectContaining({ id: ACCOUNT, name: "Production", cadenceHours: 12 }),
      intake: {
        ok: true,
        stored: true,
        retryable: false,
        tokenId: "ed17574386854bf78a67040be0a770b0",
        expiresOn: "2026-12-01T00:00:00Z",
        permissionGroups: ["Workers Metadata Read-Only", "echo [redacted]"],
        reasons: [],
        warnings: [],
      },
    });
    expect(calls).toEqual([
      { method: "store", args: [ACCOUNT, GOOD, "workload"] },
      {
        method: "addAccount",
        args: [{ id: ACCOUNT, name: "Production", profile: "workload", cadenceHours: 12 }],
      },
    ]);
    expect(raw).not.toContain(GOOD);
    expect(logs.text()).not.toContain(GOOD);
  });

  it("does not register the account when the broker rejects the token", async () => {
    const response = await onboard({ accountId: ACCOUNT, token: REJECTED, profile: "inventory" });
    const raw = await text(response.clone());
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      error: "token_rejected",
      intake: {
        ok: false,
        stored: false,
        reasons: [{ code: "not_read_only", message: "token [redacted] can write" }],
      },
    });
    expect(calls.map((c) => c.method)).toEqual(["store"]);
    expect(raw).not.toContain(REJECTED);
    expect(logs.text()).not.toContain(REJECTED);
  });

  it("answers without detail when the broker or core fails", async () => {
    const broken = await onboard({ accountId: ACCOUNT, token: THROWS, profile: "inventory" });
    const raw = await text(broken.clone());
    expect(broken.status).toBe(502);
    expect(await broken.json()).toEqual({ error: "upstream_error" });
    expect(raw).not.toContain(THROWS);

    const notAdded = await onboard({
      accountId: ACCOUNT,
      token: GOOD,
      profile: "inventory",
      name: "fail",
    });
    expect(notAdded.status).toBe(502);
    expect(await notAdded.json()).toMatchObject({ error: "account_not_added" });
    expect(logs.text()).not.toContain(THROWS);
    expect(logs.text()).not.toContain(GOOD);
    expect(logs.text()).not.toContain("vault failure");
  });

  it("validates the form before calling the broker", async () => {
    const status = async (body: unknown) => {
      const response = await onboard(body);
      return [response.status, ((await response.json()) as { error: string }).error];
    };
    const valid = { accountId: ACCOUNT, token: GOOD, profile: "inventory" };
    expect(await status([])).toEqual([400, "invalid_body"]);
    expect(await status({ ...valid, accountId: "ABC" })).toEqual([400, "invalid_account_id"]);
    expect(await status({ ...valid, token: "" })).toEqual([400, "invalid_token"]);
    expect(await status({ ...valid, token: 42 })).toEqual([400, "invalid_token"]);
    expect(await status({ ...valid, token: "x".repeat(513) })).toEqual([400, "invalid_token"]);
    expect(await status({ ...valid, profile: "admin" })).toEqual([400, "invalid_profile"]);
    expect(await status({ ...valid, name: "a\nb" })).toEqual([400, "invalid_name"]);
    expect(await status({ ...valid, name: "x".repeat(201) })).toEqual([400, "invalid_name"]);
    expect(await status({ ...valid, cadenceHours: 0 })).toEqual([400, "invalid_cadence"]);
    expect(await status({ ...valid, cadenceHours: "24" })).toEqual([400, "invalid_cadence"]);
    expect(calls).toEqual([]);
    expect(logs.text()).not.toContain(GOOD);
  });

  it("refuses bodies that are too large or not JSON", async () => {
    const big = await call("/api/accounts", {
      token: admin,
      body: { accountId: ACCOUNT, token: GOOD, profile: "inventory", pad: "x".repeat(20_000) },
    });
    expect(big.status).toBe(413);
    const broken = await call("/api/accounts", {
      method: "POST",
      token: admin,
      headers: { "content-type": "application/json", origin: "https://virga.example.com" },
    });
    expect(broken.status).toBe(400);
    expect(calls).toEqual([]);
  });

  it("defaults the name to the account ID", async () => {
    const response = await onboard({ accountId: ACCOUNT, token: GOOD, profile: "inventory" });
    expect(response.status).toBe(201);
    expect(calls[1]?.args[0]).toEqual({ id: ACCOUNT, name: ACCOUNT, profile: "inventory" });
  });

  it("scrubs a secret from nested values and keys", () => {
    expect(scrub({ a: ["xSECRETx", { SECRET: "SECRET" }], b: 1, c: null }, "SECRET")).toEqual({
      a: ["x[redacted]x", { "[redacted]": "[redacted]" }],
      b: 1,
      c: null,
    });
    expect(scrub({ a: "unchanged" }, "")).toEqual({ a: "unchanged" });
  });
});
