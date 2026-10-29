// Route tables for the fixture transport, one per collector, assembled from the
// documented examples in the sibling fixture files (sources are cited there).

import type { CfQuery } from "@virga/cf-api";
import { envelope, type FixtureRoute } from "@virga/cf-api/testing";
import { recordA, recordCname, recordTxt } from "./dns.ts";
import { directUploadProject, gitProject, gitProjectDomains, noPreviewProject } from "./pages.ts";
import {
  bucketBare,
  bucketExample,
  customDomains,
  d1Example,
  doNamespaceExample,
  doNamespaceLegacy,
  hyperdriveExample,
  hyperdriveVpc,
  kvExample,
  managedDisabled,
  managedEnabled,
  queueExample,
  secretDeleted,
  secretExample,
  storeExample,
} from "./storage.ts";
import {
  apiDeployments,
  apiWorker,
  legacySubdomain,
  legacyWorker,
  myDeployments,
  myVersionList,
  myWorker,
  routeWithoutScript,
  routeWithScript,
  V_API_1,
  V_MY_1,
  V_MY_2,
  V_MY_3,
  versionApi1,
  versionMy1,
  versionMy2,
  versionMy3,
} from "./workers.ts";
import { ZONE_A, ZONE_B, zonesRoute } from "./zones.ts";

export type Routes = Record<string, FixtureRoute>;

export const ACCOUNT = "023e105f4ecef8ad9ca31a8372d0c353";
const account = `/accounts/${ACCOUNT}`;

const info = (count: number, perPage: number) => ({
  count,
  page: 1,
  per_page: perPage,
  total_count: count,
});

const doNamespacesRoute = envelope([doNamespaceExample, doNamespaceLegacy], {
  ...info(2, 1000),
  total_pages: 1,
});
const queuesRoute = envelope([queueExample], { ...info(1, 50), total_pages: 1 });

export const zonesRoutes: Routes = { "/zones": zonesRoute() };

/** Zone A has two pages of records, zone B one. */
export const dnsRoutes: Routes = {
  "/zones": zonesRoute(),
  [`/zones/${ZONE_A}/dns_records`]: (q: CfQuery) =>
    Number(q.page) === 1
      ? envelope([recordA], { count: 1, page: 1, per_page: 5000, total_count: 2, total_pages: 2 })
      : envelope([recordCname], {
          count: 1,
          page: 2,
          per_page: 5000,
          total_count: 2,
          total_pages: 2,
        }),
  [`/zones/${ZONE_B}/dns_records`]: envelope([recordTxt], {
    count: 1,
    page: 1,
    per_page: 5000,
    total_count: 1,
    total_pages: 1,
  }),
};

const scripts = `${account}/workers/scripts`;

/** The Workers API (beta) list comes in two pages. */
export const workersRoutes: Routes = {
  "/zones": zonesRoute(),
  [`${account}/workers/workers`]: (q: CfQuery) =>
    Number(q.page) === 1
      ? envelope([myWorker, apiWorker], { count: 2, page: 1, per_page: 100, total_pages: 2 })
      : envelope([legacyWorker], { count: 1, page: 2, per_page: 100, total_pages: 2 }),
  [`${scripts}/legacy-worker/subdomain`]: envelope(legacySubdomain),
  [`${scripts}/my-worker/deployments`]: envelope(myDeployments),
  [`${scripts}/api-worker/deployments`]: envelope(apiDeployments),
  [`${scripts}/legacy-worker/deployments`]: envelope({ deployments: [] }),
  [`${scripts}/my-worker/versions`]: envelope(myVersionList),
  [`${scripts}/my-worker/versions/${V_MY_1}`]: envelope(versionMy1),
  [`${scripts}/my-worker/versions/${V_MY_2}`]: envelope(versionMy2),
  [`${scripts}/my-worker/versions/${V_MY_3}`]: envelope(versionMy3),
  [`${scripts}/api-worker/versions/${V_API_1}`]: envelope(versionApi1),
  [`${account}/workers/durable_objects/namespaces`]: doNamespacesRoute,
  [`${account}/queues`]: queuesRoute,
  [`/zones/${ZONE_A}/workers/routes`]: envelope([routeWithScript, routeWithoutScript]),
  [`/zones/${ZONE_B}/workers/routes`]: envelope([]),
};

const projects = `${account}/pages/projects`;

/** The project list comes in two pages. */
export const pagesRoutes: Routes = {
  [projects]: (q: CfQuery) =>
    Number(q.page) === 1
      ? envelope([gitProject, noPreviewProject], { count: 2, page: 1, total_pages: 2 })
      : envelope([directUploadProject], { count: 1, page: 2, total_pages: 2 }),
  [`${projects}/this-is-my-project-01`]: envelope(gitProject),
  [`${projects}/docs`]: envelope(noPreviewProject),
  [`${projects}/landing`]: envelope(directUploadProject),
  [`${projects}/this-is-my-project-01/domains`]: envelope(gitProjectDomains, {
    count: 2,
    page: 1,
    total_pages: 1,
  }),
  [`${projects}/docs/domains`]: envelope([], { count: 0, page: 1, total_pages: 1 }),
  [`${projects}/landing/domains`]: envelope([], { count: 0, page: 1, total_pages: 1 }),
  [`${account}/queues`]: queuesRoute,
};

export const storageRoutes: Routes = {
  [`${account}/r2/buckets`]: envelope(
    { buckets: [bucketExample, bucketBare] },
    { total_count: 2, per_page: 1000 },
  ),
  [`${account}/r2/buckets/example-bucket/domains/managed`]: envelope(managedEnabled),
  [`${account}/r2/buckets/example-bucket/domains/custom`]: envelope(customDomains),
  [`${account}/r2/buckets/logs/domains/managed`]: envelope(managedDisabled),
  [`${account}/r2/buckets/logs/domains/custom`]: envelope({ domains: [] }),
  [`${account}/d1/database`]: envelope([d1Example], info(1, 1000)),
  [`${account}/storage/kv/namespaces`]: envelope([kvExample], info(1, 1000)),
  [`${account}/queues`]: queuesRoute,
  [`${account}/hyperdrive/configs`]: envelope([hyperdriveExample, hyperdriveVpc], info(2, 100)),
  [`${account}/workers/durable_objects/namespaces`]: doNamespacesRoute,
  [`${account}/secrets_store/stores`]: envelope([storeExample], {
    ...info(1, 100),
    total_pages: 1,
  }),
  [`${account}/secrets_store/stores/${storeExample.id}/secrets`]: envelope(
    [secretExample, secretDeleted],
    { ...info(2, 100), total_pages: 1 },
  ),
};
