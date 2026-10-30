import { type DependencyList, type ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError } from "./api.ts";

export interface Loaded<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

/** Runs `load` when `deps` change and drops results that arrive after a newer request. */
export function useLoad<T>(load: () => Promise<T>, deps: DependencyList): Loaded<T> {
  const [state, setState] = useState<{ data?: T; error?: Error; loading: boolean }>({
    loading: true,
  });
  const [round, setRound] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `deps` stand in for `load`.
  useEffect(() => {
    let current = true;
    setState((s) => ({ ...s, loading: true }));
    load().then(
      (data) => current && setState({ data, loading: false }),
      (error: unknown) =>
        current &&
        setState({ error: error instanceof Error ? error : new Error("failed"), loading: false }),
    );
    return () => {
      current = false;
    };
  }, [...deps, round]);
  const reload = useCallback(() => setRound((r) => r + 1), []);
  return { ...state, reload } as Loaded<T>;
}

const MESSAGES: Record<number, string> = {
  403: "Access denied.",
  404: "Not found: the account is not onboarded, or the item does not exist.",
  502: "The graph could not be read. Try again later.",
};

export function Problem({ error }: { error: Error }) {
  const message =
    error instanceof ApiError
      ? (MESSAGES[error.status] ?? `Request failed (${error.status} ${error.code}).`)
      : "The request failed. Check the connection and reload.";
  return (
    <p className="problem" role="alert">
      {message}
    </p>
  );
}

export function Pending<T>({
  loaded,
  children,
}: {
  loaded: Loaded<T>;
  children: (data: T) => ReactNode;
}) {
  if (loaded.error) return <Problem error={loaded.error} />;
  if (loaded.data === undefined) return <p className="muted">Loading…</p>;
  return <>{children(loaded.data)}</>;
}
