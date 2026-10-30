import type { Me } from "./api.ts";
import { api } from "./api.ts";
import { useLoad } from "./load.tsx";
import { AccountPage, AccountsPage, AuditPage, FindingPage, OnboardingPage } from "./pages.tsx";
import { Link, match, paths, useLocation } from "./router.tsx";

/** The top bar; the audit trail is linked for admins only. */
export function Header({ me }: { me: Me | undefined }) {
  return (
    <header>
      <Link to={paths.accounts()}>Virga</Link>
      <span className="muted">read-only security graph</span>
      {me?.admin && <Link to={paths.audit()}>Audit trail</Link>}
      <span className="who">
        {me?.email ?? me?.serviceToken ?? ""}
        {me?.admin && " (admin)"}
      </span>
    </header>
  );
}

/** The non-affiliation notice (D-01), on every page. Text only: no Cloudflare logo. */
export function Footer() {
  return (
    <footer>
      Virga is an independent open source project. It is not affiliated with, endorsed by, or
      sponsored by Cloudflare, Inc.
    </footer>
  );
}

export function App() {
  const location = useLocation();
  const me = useLoad(() => api.me(), []);
  const route = match(location);
  return (
    <>
      <Header me={me.data} />
      <main>
        {route.page === "accounts" && <AccountsPage me={me.data} />}
        {route.page === "account" && <AccountPage accountId={route.accountId} me={me.data} />}
        {route.page === "finding" && (
          <FindingPage accountId={route.accountId} fingerprint={route.fingerprint} />
        )}
        {route.page === "onboarding" && <OnboardingPage me={me.data} />}
        {route.page === "audit" && <AuditPage me={me.data} />}
        {route.page === "not_found" && <p className="problem">This page does not exist.</p>}
      </main>
      <Footer />
    </>
  );
}
