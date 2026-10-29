import { type NodeType, nodeId } from "@virga/graph";
import type { CollectorContext } from "../types.ts";
import { listDoNamespaces, listQueues } from "./lists.ts";
import { str } from "./util.ts";

/** A binding as the Workers API returns it: `type`, `name` and type-specific fields. */
export type Binding = Record<string, unknown>;

/**
 * Bindings name queues by name and own Durable Objects by class, while the
 * graph keys those nodes by ID. The lookups load each list at most once per chunk.
 */
export interface StoreLookup {
  queueId(name: string): Promise<string | null>;
  doNamespaceId(script: string, className: string): Promise<string | null>;
}

export function storeLookup(ctx: CollectorContext): StoreLookup {
  let queues: Promise<Map<string, string>> | undefined;
  let namespaces: Promise<Map<string, string>> | undefined;
  return {
    async queueId(name) {
      queues ??= listQueues(ctx).then((list) => {
        const map = new Map<string, string>();
        for (const q of list) {
          const id = str(q.queue_id);
          const queueName = str(q.queue_name);
          if (id && queueName) map.set(queueName, id);
        }
        return map;
      });
      return (await queues).get(name) ?? null;
    },
    async doNamespaceId(script, className) {
      namespaces ??= listDoNamespaces(ctx).then((list) => {
        const map = new Map<string, string>();
        for (const ns of list) {
          const id = str(ns.id);
          const nsScript = str(ns.script);
          const nsClass = str(ns.class);
          if (id && nsScript && nsClass) map.set(`${nsScript}\u0000${nsClass}`, id);
        }
        return map;
      });
      return (await namespaces).get(`${script}\u0000${className}`) ?? null;
    },
  };
}

/**
 * The node a binding points to, following the binding target table of the
 * graph contract, or null for binding types without a node (AI, analytics
 * engine, browser, ...) and for targets that cannot be resolved.
 */
export async function bindingTarget(
  binding: Binding,
  script: string,
  lookup: StoreLookup,
): Promise<string | null> {
  const ref = (type: NodeType, id: string | null) => (id ? nodeId(type, id) : null);
  switch (binding.type) {
    case "kv_namespace":
      return ref("kv_namespace", str(binding.namespace_id));
    case "d1":
      return ref("d1_database", str(binding.database_id) ?? str(binding.id));
    case "r2_bucket":
      return ref("r2_bucket", str(binding.bucket_name));
    case "durable_object_namespace": {
      const id = str(binding.namespace_id);
      if (id) return ref("do_namespace", id);
      const className = str(binding.class_name);
      if (!className) return null;
      const owner = str(binding.script_name) ?? script;
      return ref("do_namespace", await lookup.doNamespaceId(owner, className));
    }
    case "service":
      return ref("worker_script", str(binding.service));
    case "queue": {
      const name = str(binding.queue_name);
      return ref("queue", name ? await lookup.queueId(name) : null);
    }
    case "hyperdrive":
      return ref("hyperdrive_config", str(binding.id));
    case "secrets_store_secret": {
      const store = str(binding.store_id);
      const secret = str(binding.secret_name);
      return ref("secrets_store_secret", store && secret ? `${store}/${secret}` : null);
    }
    case "vectorize":
      return ref("vectorize_index", str(binding.index_name));
    default:
      return null;
  }
}
