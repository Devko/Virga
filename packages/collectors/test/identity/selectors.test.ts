import { describe, expect, it } from "vitest";
import { selectedNode, selector, selectors } from "../../src/identity/selectors.ts";

// Rule shapes: the AccessRule union in
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list/

const IDP = "699d98642c564d2e855e9661899b7252";

describe("selector", () => {
  const cases: [object, ReturnType<typeof selector>][] = [
    [{ everyone: {} }, { kind: "everyone", value: null }],
    [{ any_valid_service_token: {} }, { kind: "any_valid_service_token", value: null }],
    [{ certificate: {} }, { kind: "certificate", value: null }],
    [{ email: { email: "a@example.com" } }, { kind: "email", value: "a@example.com" }],
    [{ email_domain: { domain: "example.com" } }, { kind: "email_domain", value: "example.com" }],
    [{ email_list: { id: "l1" } }, { kind: "email_list", value: "l1" }],
    [{ group: { id: "g1" } }, { kind: "group", value: "g1" }],
    [{ service_token: { token_id: "t1" } }, { kind: "service_token", value: "t1" }],
    [{ login_method: { id: IDP } }, { kind: "login_method", value: IDP }],
    [{ ip: { ip: "10.0.0.0/8" } }, { kind: "ip", value: "10.0.0.0/8" }],
    [{ geo: { country_code: "US" } }, { kind: "geo", value: "US" }],
    [{ device_posture: { integration_uid: "p1" } }, { kind: "device_posture", value: "p1" }],
    [{ common_name: { common_name: "cn" } }, { kind: "common_name", value: "cn" }],
    [
      { okta: { identity_provider_id: IDP, name: "admins" } },
      { kind: "idp_group", value: { idp: IDP, name: "admins" } },
    ],
    [
      { azureAD: { id: "aad1", identity_provider_id: IDP } },
      { kind: "idp_group", value: { idp: IDP, name: "aad1" } },
    ],
    [
      { gsuite: { email: "devs@example.com", identity_provider_id: IDP } },
      { kind: "idp_group", value: { idp: IDP, name: "devs@example.com" } },
    ],
    [
      { "github-organization": { identity_provider_id: IDP, name: "acme" } },
      { kind: "idp_group", value: { idp: IDP, name: "acme" } },
    ],
    [
      { "github-organization": { identity_provider_id: IDP, name: "acme", team: "ops" } },
      { kind: "idp_group", value: { idp: IDP, name: "acme/ops" } },
    ],
    [
      { saml: { attribute_name: "role", attribute_value: "admin", identity_provider_id: IDP } },
      { kind: "idp_group", value: { idp: IDP, name: "role=admin" } },
    ],
    [
      { oidc: { claim_name: "groups", claim_value: "sre", identity_provider_id: IDP } },
      { kind: "idp_group", value: { idp: IDP, name: "groups=sre" } },
    ],
  ];
  it.each(cases)("maps %j", (rule, expected) => {
    expect(selector(rule)).toEqual(expected);
  });

  const others: unknown[] = [
    { ip_list: { id: "l1" } },
    { auth_method: { auth_method: "mfa" } },
    { auth_context: { id: "c", ac_id: "c1", identity_provider_id: IDP } },
    { external_evaluation: { evaluate_url: "https://e.example.com", keys_url: "https://k" } },
    { linked_app_token: { app_uid: "a" } },
    { user_risk_score: { user_risk_score: ["high"] } },
    { cloudflare_account_member: { account_id: "x" } },
    // Malformed: missing values, several keys, not an object.
    { email: {} },
    { okta: { name: "no idp" } },
    { email: { email: "a@example.com" }, ip: { ip: "1.1.1.1" } },
    { everyone: true },
    "everyone",
    null,
  ];
  it.each(others)("maps %j to other with the raw rule", (rule) => {
    expect(selector(rule)).toEqual({ kind: "other", value: rule });
  });

  it("maps an overlong value to other with a bounded raw rule", () => {
    const long = `${"a".repeat(600)}@example.com`;
    const s = selector({ email: { email: long } });
    expect(s.kind).toBe("other");
    expect(JSON.stringify(s).length).toBeLessThan(400);
    expect(selector({ okta: { identity_provider_id: IDP, name: long } }).kind).toBe("other");
  });
});

describe("selectors", () => {
  it("sorts and deduplicates, and tolerates a missing list", () => {
    expect(selectors([{ group: { id: "b" } }, { everyone: {} }, { group: { id: "b" } }])).toEqual([
      { kind: "everyone", value: null },
      { kind: "group", value: "b" },
    ]);
    expect(selectors(undefined)).toEqual([]);
  });

  it("points at the node a selector names", () => {
    expect(selectedNode({ kind: "everyone", value: null })).toBe("everyone:everyone");
    expect(selectedNode({ kind: "group", value: "g" })).toBe("access_group:g");
    expect(selectedNode({ kind: "service_token", value: "t" })).toBe("service_token:t");
    expect(selectedNode({ kind: "login_method", value: IDP })).toBe(`identity_provider:${IDP}`);
    expect(selectedNode({ kind: "idp_group", value: { idp: IDP, name: "x" } })).toBe(
      `identity_provider:${IDP}`,
    );
    expect(selectedNode({ kind: "email", value: "a@example.com" })).toBeNull();
    expect(selectedNode({ kind: "any_valid_service_token", value: null })).toBeNull();
  });
});
