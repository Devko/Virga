import { type MouseEvent, type ReactNode, useEffect, useState } from "react";

/** A small history router: four pages need no routing library. */

export function navigate(to: string): void {
  window.history.pushState(null, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo(0, 0);
}

export function useLocation(): URL {
  const [location, setLocation] = useState(() => new URL(window.location.href));
  useEffect(() => {
    const update = () => setLocation(new URL(window.location.href));
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  return location;
}

/** In-app link. `to` is always a path built by this app, never a value from an account. */
export function Link({ to, children }: { to: string; children: ReactNode }) {
  const onClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    event.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} onClick={onClick}>
      {children}
    </a>
  );
}

export const paths = {
  accounts: () => "/",
  account: (id: string) => `/accounts/${encodeURIComponent(id)}`,
  finding: (id: string, fingerprint: string) =>
    `/accounts/${encodeURIComponent(id)}/finding?${new URLSearchParams({ fp: fingerprint })}`,
  onboarding: () => "/onboarding",
  audit: () => "/audit",
};

export type Route =
  | { page: "accounts" }
  | { page: "account"; accountId: string }
  | { page: "finding"; accountId: string; fingerprint: string }
  | { page: "onboarding" }
  | { page: "audit" }
  | { page: "not_found" };

const ACCOUNT_ID = /^[0-9a-f]{32}$/;

export function match(url: URL): Route {
  const parts = url.pathname.split("/").filter((p) => p !== "");
  if (parts.length === 0) return { page: "accounts" };
  if (parts.length === 1 && parts[0] === "onboarding") return { page: "onboarding" };
  if (parts.length === 1 && parts[0] === "audit") return { page: "audit" };
  if (parts[0] === "accounts" && parts[1] && ACCOUNT_ID.test(parts[1])) {
    const accountId = parts[1];
    if (parts.length === 2) return { page: "account", accountId };
    const fingerprint = url.searchParams.get("fp");
    if (parts.length === 3 && parts[2] === "finding" && fingerprint) {
      return { page: "finding", accountId, fingerprint };
    }
  }
  return { page: "not_found" };
}
