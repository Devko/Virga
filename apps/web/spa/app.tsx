import { api } from "./api.ts";
import { useLoad } from "./load.tsx";
import { AccountPage, AccountsPage, FindingPage, OnboardingPage } from "./pages.tsx";
import { Link, match, paths, useLocation } from "./router.tsx";

export function App() {
  const location = useLocation();
  const me = useLoad(() => api.me(), []);
  const route = match(location);
  return (
    <>
      <header>
        <Link to={paths.accounts()}>Virga</Link>
        <span className="muted">read-only security graph</span>
        <span className="who">
          {me.data?.email ?? me.data?.serviceToken ?? ""}
          {me.data?.admin && " (admin)"}
        </span>
      </header>
      <main>
        {route.page === "accounts" && <AccountsPage me={me.data} />}
        {route.page === "account" && <AccountPage accountId={route.accountId} me={me.data} />}
        {route.page === "finding" && (
          <FindingPage accountId={route.accountId} fingerprint={route.fingerprint} />
        )}
        {route.page === "onboarding" && <OnboardingPage me={me.data} />}
        {route.page === "not_found" && <p className="problem">This page does not exist.</p>}
      </main>
    </>
  );
}
