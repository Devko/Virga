import { describe, expect, it } from "vitest";
import { checkReadOnlyDocument, MAX_DOCUMENT_LENGTH } from "../src/graphql.ts";

// Query shapes from
// https://developers.cloudflare.com/analytics/graphql-api/getting-started/execute-graphql-query/
const ANALYTICS_QUERY = `query Traffic($accountTag: string!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(limit: 100, filter: $filter, orderBy: [sum_requests_DESC]) {
        sum { requests }
        dimensions { scriptName }
      }
    }
  }
}`;

describe("GraphQL read-only check", () => {
  it.each([
    ["a named query", ANALYTICS_QUERY],
    ["the shorthand form", "{ viewer { zones(filter: { zoneTag: $zoneTag }) { zoneTag } } }"],
    ["a query with fragments", "query { viewer { ...F } } fragment F on viewer { budget }"],
    ["default object values", 'query Q($f: Filter = { a: "}" }) @cached(ttl: { s: 1 }) { a }'],
    ["mutation inside a string", 'query { a(note: "mutation { x }") }'],
    ["mutation inside a block string", 'query { a(note: """mutation { x } \\""" """) }'],
    ["mutation inside a comment", "# mutation { x }\nquery { a }"],
    ["a field named mutation", "query { mutation subscription { a } }"],
  ])("accepts %s", (_, document) => {
    expect(checkReadOnlyDocument(document)).toEqual({ ok: true });
  });

  it.each([
    ["a mutation", "mutation { deleteZone(id: 1) { id } }"],
    ["a named mutation", "mutation Drop($id: ID!) { drop(id: $id) }"],
    ["a subscription", "subscription { events { id } }"],
    ["a mutation after a query", "query { a } mutation { b }"],
    ["a mutation after a fragment", "fragment F on X { a } mutation { b }"],
    ["a mutation after a comment line", "# query\nmutation { b }"],
  ])("refuses %s", (_, document) => {
    const result = checkReadOnlyDocument(document);
    expect(result.ok).toBe(false);
    expect(result.ok || result.reason).toMatch(/mutation|subscription/);
  });

  it.each([
    ["an empty document", ""],
    ["a non-string", 42],
    ["unbalanced braces", "query { a { b }"],
    ["an unterminated string", 'query { a(x: "y) }'],
    ["a type definition", "type Query { a: Int }"],
    ["a schema extension", "extend type Query { a: Int }"],
    ["only fragments", "fragment F on X { a }"],
    ["stray characters", "query { a } %"],
    ["a definition without selection set", "query Q"],
    ["a too long document", `{ a }${" ".repeat(MAX_DOCUMENT_LENGTH)}`],
  ])("refuses %s", (_, document) => {
    expect(checkReadOnlyDocument(document).ok).toBe(false);
  });
});
