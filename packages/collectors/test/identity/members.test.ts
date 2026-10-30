import { describe, expect, it } from "vitest";
import { membersCollector } from "../../src/identity/members.ts";
import {
  MEMBERS,
  memberExample,
  memberOwner,
  memberPending,
  memberPolicy,
} from "./fixtures/members.ts";
import { membersRoutes } from "./fixtures/routes.ts";
import {
  BASE,
  denied,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  nodeIds,
  run,
} from "./helpers.ts";

const routes = membersRoutes;

describe("members collector", () => {
  it("lists members until a short page", async () => {
    const { chunks, calls, output } = await run(membersCollector, routes);
    expect(chunks).toEqual([[]]);
    expect(calls).toEqual([
      `GET ${BASE}/members?page=1&per_page=50`,
      `GET ${BASE}/members?page=2&per_page=50`,
    ]);
    expect(nodeIds(output, "member")).toHaveLength(MEMBERS.length);
  });

  it("emits member nodes with roles from roles and allow policies", async () => {
    const { output } = await run(membersCollector, routes);
    expectProps(output, "member", ["status", "roles", "super_admin", "two_factor_enabled"]);
    expect(node(output, `member:${memberExample.id}`)).toEqual({
      type: "member",
      nativeId: memberExample.id,
      name: "user@example.com",
      props: {
        status: "accepted",
        roles: ["Account Administrator", "Magic Network Monitoring", "Zone Read"],
        super_admin: false,
        two_factor_enabled: true,
      },
    });
  });

  it("marks Super Administrators, through a legacy role or a policy", async () => {
    const { output } = await run(membersCollector, routes);
    // No top-level email: the user's email is the name.
    expect(node(output, `member:${memberOwner.id}`)).toMatchObject({
      name: "owner@example.com",
      props: {
        roles: ["Super Administrator - All Privileges"],
        super_admin: true,
        two_factor_enabled: false,
      },
    });
    // A deny policy grants no role. Without a user object 2FA is unknown, not false.
    expect(node(output, `member:${memberPolicy.id}`).props).toEqual({
      status: "accepted",
      roles: ["Super Administrator - All Privileges"],
      super_admin: true,
      two_factor_enabled: null,
    });
    expect(node(output, `member:${memberPending.id}`).props).toEqual({
      status: "pending",
      roles: [],
      super_admin: false,
      two_factor_enabled: null,
    });
  });

  it("is deterministic", async () => {
    await expectDeterministic(membersCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(membersCollector, { [`${BASE}/members`]: denied() });
  });
});
