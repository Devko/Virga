// Source: https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
// The A record is the documented 200 example; the CNAME and TXT records follow
// the CNAMERecord and TXTRecord schemas on the same page.

export const recordA = {
  name: "example.com",
  ttl: 3600,
  type: "A",
  comment: "Domain verification record",
  content: "198.51.100.4",
  private_routing: true,
  proxied: true,
  settings: { ipv4_only: true, ipv6_only: true },
  tags: ["owner:dns-team"],
  id: "023e105f4ecef8ad9ca31a8372d0c353",
  created_on: "2014-01-01T05:20:00.12345Z",
  meta: {
    dead_glue: true,
    is_glue: true,
    shadowed_by: ["372e67954025e0ba6aaa6d586b9e0b59"],
    shadowed_records_count: 42,
  },
  modified_on: "2014-01-01T05:20:00.12345Z",
  proxiable: true,
  comment_modified_on: "2024-01-01T05:20:00.12345Z",
  tags_modified_on: "2025-01-01T05:20:00.12345Z",
};

export const recordCname = {
  name: "www.example.com",
  ttl: 1,
  type: "CNAME",
  content: "example.com",
  proxied: false,
  settings: {},
  tags: [],
  id: "372e67954025e0ba6aaa6d586b9e0b59",
  created_on: "2014-01-01T05:20:00.12345Z",
  meta: {},
  modified_on: "2014-01-01T05:20:00.12345Z",
  proxiable: true,
};

export const recordTxt = {
  name: "example.org",
  ttl: 300,
  type: "TXT",
  content: '"v=spf1 -all"',
  proxied: false,
  settings: {},
  tags: [],
  id: "699d98642c564d2e855e9661899b7252",
  created_on: "2015-03-01T05:20:00.12345Z",
  meta: {},
  modified_on: "2015-03-01T05:20:00.12345Z",
  proxiable: false,
};
