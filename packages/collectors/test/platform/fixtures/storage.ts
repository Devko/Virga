// Sources, one per listing, each built from the documented 200 example:
// https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list/
// https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/subresources/managed/methods/list/
// https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/subresources/custom/methods/list/
// https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/list/
// https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/methods/list/
// https://developers.cloudflare.com/api/resources/queues/methods/list/
// https://developers.cloudflare.com/api/resources/hyperdrive/subresources/configs/methods/list/
// https://developers.cloudflare.com/api/resources/durable_objects/subresources/namespaces/methods/list/
// https://developers.cloudflare.com/api/resources/secrets_store/subresources/stores/methods/list/
// https://developers.cloudflare.com/api/resources/secrets_store/subresources/stores/subresources/secrets/methods/list/

export const bucketExample = {
  creation_date: "2024-05-01T12:00:00.000Z",
  jurisdiction: "default",
  location: "apac",
  name: "example-bucket",
  storage_class: "Standard",
};

// Optional fields omitted.
export const bucketBare = { name: "logs" };

/** Managed r2.dev domain: `result` of GET .../domains/managed. */
export const managedEnabled = {
  bucketId: "0113a9e4549cf9b1ff1bf56e04da0cef",
  domain: "pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev",
  enabled: true,
};

export const managedDisabled = {
  bucketId: "64a5c7c3a5d24a0d8a3d0e7f2b1c9e88",
  domain: "pub-64a5c7c3a5d24a0d8a3d0e7f2b1c9e88.r2.dev",
  enabled: false,
};

/** `result` of GET .../domains/custom. */
export const customDomains = {
  domains: [
    {
      domain: "prefix.example-domain.one.com",
      enabled: false,
      status: { ownership: "deactivated", ssl: "pending" },
      ciphers: ["string"],
      minTLS: "1.0",
      zoneId: "36ca64a6d92827b8a6b90be344bb1bfd",
      zoneName: "example-domain.one.com",
    },
    {
      domain: "prefix.example-domain.two.com",
      enabled: true,
      status: { ownership: "active", ssl: "active" },
      ciphers: ["string"],
      minTLS: "1.0",
      zoneId: "d9d28585d5f8f5b0f857b055bf574f19",
      zoneName: "zoneName",
    },
  ],
};

export const d1Example = {
  created_at: "2022-11-15T18:25:44.442097Z",
  jurisdiction: "eu",
  name: "my-database",
  uuid: "445e2955-951a-43f8-a35b-a4d0c8138f63",
  version: "production",
};

export const kvExample = {
  id: "0f2ac74b498b48028cb68387c421e279",
  title: "My Own Namespace",
  jurisdiction: "eu",
  mode: "instant",
  supports_url_encoding: true,
};

export const queueExample = {
  consumers: [
    {
      consumer_id: "023e105f4ecef8ad9ca31a8372d0c353",
      created_on: "2019-12-27T18:11:19.117Z",
      dead_letter_queue: "dead_letter_queue",
      queue_name: "example-queue",
      script_name: "my-consumer-worker",
      settings: {
        batch_size: 50,
        max_concurrency: 10,
        max_retries: 3,
        max_wait_time_ms: 5000,
        retry_delay: 10,
      },
      type: "worker",
    },
  ],
  consumers_total_count: 1,
  created_on: "2019-12-27T18:11:19.117Z",
  modified_on: "2019-12-27T18:11:19.117Z",
  producers: [{ script: "my-worker", type: "worker" }],
  producers_total_count: 1,
  queue_id: "b7e0a1c4d2f34e5a9c8b7a6d5e4f3a21",
  queue_name: "example-queue",
  settings: { delivery_delay: 5, delivery_paused: true, message_retention_period: 345600 },
};

/** Hyperdrive never returns the origin password (write-only per the reference). */
export const hyperdriveExample = {
  id: "a76a99bc342644deb02c38d66082262a",
  caching: { disabled: true, max_age: 1, stale_while_revalidate: 0 },
  name: "example-hyperdrive",
  origin: {
    database: "postgres",
    host: "database.example.com",
    port: 5432,
    scheme: "postgres",
    user: "postgres",
  },
  created_on: "2017-01-01T00:00:00Z",
  modified_on: "2017-01-01T00:00:00Z",
  origin_connection_limit: 60,
};

/** An origin reached through a Workers VPC service has no host. */
export const hyperdriveVpc = {
  id: "c1d2e3f4a5b647c8d9e0f1a2b3c4d5e6",
  caching: { disabled: false },
  name: "vpc-hyperdrive",
  origin: { database: "app", scheme: "mysql", service_id: "vpc-service-1", user: "app" },
};

export const doNamespaceExample = {
  id: "5eb63bbbe01eeed093cb22bb8f5acdc3",
  class: "Counter",
  name: "my-worker_Counter",
  script: "my-worker",
  use_sqlite: true,
};

export const doNamespaceLegacy = {
  id: "7a1f0d2e9c3b4a5d8e6f7a8b9c0d1e2f",
  class: "Room",
  name: "chat_Room",
  script: "chat",
  use_sqlite: false,
};

export const storeExample = {
  id: "023e105f4ecef8ad9ca31a8372d0c353",
  created: "2023-09-21T18:56:32.624632Z",
  modified: "2023-09-21T18:56:32.624632Z",
  name: "service_x_keys",
  account_id: "985e105f4ecef8ad9ca31a8372d0c353",
};

export const secretExample = {
  id: "3fd85f74b32742f1bff64a85009dda07",
  created: "2023-09-21T18:56:32.624632Z",
  modified: "2023-09-21T18:56:32.624632Z",
  name: "MY_API_KEY",
  status: "pending",
  store_id: "023e105f4ecef8ad9ca31a8372d0c353",
  comment: "info about my secret",
  scopes: ["workers", "ai_gateway", "dex", "access", "websearch"],
};

export const secretDeleted = {
  ...secretExample,
  id: "8c1b2a3d4e5f60718293a4b5c6d7e8f9",
  name: "OLD_KEY",
  status: "deleted",
};
