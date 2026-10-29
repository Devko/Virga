import { NoPermissionError, NotAllowedError, RateLimitedError } from "@virga/cf-api";
import type { Collector } from "@virga/collectors";
import { describe, expect, it } from "vitest";
import { orderCollectors } from "../src/scan/order.ts";
import { apiRetryDelay, settle } from "../src/scan/step.ts";
import { serverError } from "./stubs.ts";

const collector = (resourceClass: Collector["resourceClass"], after?: Collector["after"]) =>
  ({
    resourceClass,
    after,
    permissions: [],
    plan: async () => [[]],
    collect: async () => ({ nodes: [], edges: [] }),
  }) satisfies Collector;

describe("collector order", () => {
  it("runs classes after the classes they point to, keeping input order otherwise", () => {
    const order = orderCollectors([
      collector("pages", ["storage", "workers"]),
      collector("zones"),
      collector("workers", ["storage"]),
      collector("storage"),
      collector("dns"),
    ]).map((c) => c.resourceClass);
    expect(order).toEqual(["zones", "storage", "workers", "pages", "dns"]);
  });

  it("ignores dependencies on classes without a collector", () => {
    expect(orderCollectors([collector("pages", ["access"])]).map((c) => c.resourceClass)).toEqual([
      "pages",
    ]);
  });

  it("rejects cycles and duplicate classes", () => {
    expect(() =>
      orderCollectors([collector("dns", ["zones"]), collector("zones", ["dns"])]),
    ).toThrow(/cycle/);
    expect(() => orderCollectors([collector("dns"), collector("dns")])).toThrow(/two collectors/);
  });
});

describe("step errors", () => {
  it("settles permanent errors as results and rethrows the rest for retry", () => {
    expect(settle(new NoPermissionError(403, "/zones", [{ code: 10000, message: "x" }]))).toEqual({
      status: "no_permission",
      detail: expect.stringContaining("NoPermissionError"),
    });
    expect(settle(new NotAllowedError("/zones/x/settings")).status).toBe("error");
    expect(settle(new TypeError("bad output")).status).toBe("error");
    expect(() => settle(serverError("/zones"))).toThrow(/500/);
    expect(() => settle(new Error("Network connection lost."))).toThrow();
  });

  it("waits out the broker's rate budget and backs off otherwise", () => {
    const limited = new RateLimitedError("/zones", [], 120);
    expect(apiRetryDelay({ ctx: { attempt: 1 }, error: limited })).toBe("120 seconds");
    expect(apiRetryDelay({ ctx: { attempt: 1 }, error: new Error("429 on /zones: x") })).toBe(
      "300 seconds",
    );
    expect(apiRetryDelay({ ctx: { attempt: 1 }, error: serverError("/zones") })).toBe("15 seconds");
    expect(apiRetryDelay({ ctx: { attempt: 3 }, error: serverError("/zones") })).toBe("60 seconds");
  });
});
