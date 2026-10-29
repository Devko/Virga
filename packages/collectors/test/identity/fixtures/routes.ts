// Route tables for the fixture transport, one per collector, assembled from the
// documented examples in the sibling fixture files (sources are cited there).

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";
import { BASE, type Routes } from "../helpers.ts";
import {
  APP_POLICIES,
  appsRoute,
  groupContractors,
  groupEng,
  idpOkta,
  idpOtp,
  listInfo,
  policyDevs,
  policyUnused,
  tokenCi,
  tokenIdle,
  workers,
} from "./access.ts";
import { exampleIssue, insightsRoute } from "./insights.ts";
import { MEMBERS, membersRoute } from "./members.ts";
import { TOKENS, tokensRoute } from "./tokens.ts";
import { workersListRoute } from "./traffic.ts";
import { BLOG, blogConfig, LEGACY, legacyConfig, TUNNELS, tunnelsRoute } from "./tunnels.ts";

const workersList = (q: CfQuery) =>
  envelope(workers, { count: workers.length, page: Number(q.page), per_page: 100, total_pages: 1 });

export const accessRoutes: Routes = {
  [`${BASE}/access/apps`]: appsRoute(),
  ...Object.fromEntries(
    Object.entries(APP_POLICIES).map(([id, policies]) => [
      `${BASE}/access/apps/${id}/policies`,
      envelope(policies, listInfo(policies.length)),
    ]),
  ),
  [`${BASE}/access/policies`]: envelope([policyDevs, policyUnused], listInfo(2)),
  [`${BASE}/access/groups`]: envelope([groupEng, groupContractors], listInfo(2)),
  [`${BASE}/access/service_tokens`]: envelope([tokenCi, tokenIdle], listInfo(2)),
  [`${BASE}/access/identity_providers`]: envelope([idpOtp, idpOkta], listInfo(2)),
  [`${BASE}/workers/workers`]: workersList,
};

export const tunnelsRoutes: Routes = {
  [`${BASE}/tunnels`]: tunnelsRoute(TUNNELS),
  [`${BASE}/cfd_tunnel/${BLOG}/configurations`]: envelope(blogConfig),
  [`${BASE}/cfd_tunnel/${LEGACY}/configurations`]: envelope(legacyConfig),
};

export const tokensRoutes: Routes = { [`${BASE}/tokens`]: tokensRoute(TOKENS) };

export const membersRoutes: Routes = { [`${BASE}/members`]: membersRoute(MEMBERS) };

export const insightsRoutes: Routes = {
  [`${BASE}/security-center/insights`]: insightsRoute([exampleIssue]),
};

export const trafficRoutes: Routes = { [`${BASE}/workers/workers`]: workersListRoute };
