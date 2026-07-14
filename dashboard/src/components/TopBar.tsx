import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchMe, fetchTenants, getTenant, setTenant, logout } from "../api/client";

/* Microsoft Teams-style top command bar: window controls feel, centered search, avatar. */
export default function TopBar() {
  const queryClient = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: fetchMe });
  const { data: tenants } = useQuery({ queryKey: ["tenants"], queryFn: fetchTenants });

  const current = getTenant() ?? "default";
  const switchOrg = (org: string) => {
    setTenant(org === "default" ? null : org);
    queryClient.clear();
    // Reload for a clean swap of all tenant-scoped data.
    window.location.reload();
  };

  const initials = me?.username
    ? me.username.replace(/^apikey:/, "").slice(0, 2).toUpperCase()
    : "DY";

  const doLogout = async () => {
    await logout();
    queryClient.clear();
    window.dispatchEvent(new Event("qw-unauthorized"));
  };

  return (
    <header className="fixed left-56 right-0 top-0 z-40 flex h-12 items-center gap-4 border-b border-white/[0.06] bg-surface-950 px-4">
      {/* Back / forward chevrons (decorative, Teams chrome) */}
      <div className="flex items-center gap-1 text-gray-500">
        <button className="flex h-7 w-7 items-center justify-center rounded hover:bg-white/5" aria-label="Back">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5 8.25 12l7.5-7.5" />
          </svg>
        </button>
        <button className="flex h-7 w-7 items-center justify-center rounded hover:bg-white/5" aria-label="Forward">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
          </svg>
        </button>
      </div>

      {/* Centered search */}
      <div className="flex flex-1 justify-center">
        <div className="flex w-full max-w-md items-center gap-2 rounded-md bg-surface-850 px-3 py-1.5 text-gray-400">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
          </svg>
          <input
            type="text"
            placeholder="Search assets, findings, sessions"
            className="w-full bg-transparent text-[13px] text-gray-200 placeholder:text-gray-500 outline-none"
          />
        </div>
      </div>

      {/* Right cluster: org switcher + user + logout */}
      <div className="flex items-center gap-2">
        {tenants?.canSwitch && (tenants.tenants.length ?? 0) > 0 && (
          <label className="flex items-center gap-1.5 rounded-md border border-white/10 bg-surface-850 px-2 py-1 text-xs text-gray-300" title="Switch organization / tenant">
            <svg className="h-3.5 w-3.5 text-gray-500" fill="none" viewBox="0 0 24 24" strokeWidth={1.6} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21" />
            </svg>
            <select
              value={current}
              onChange={(e) => switchOrg(e.target.value)}
              className="bg-transparent text-xs text-gray-200 outline-none"
            >
              {tenants.tenants.map((t) => (
                <option key={t} value={t} className="bg-surface-900">{t}</option>
              ))}
            </select>
          </label>
        )}
        {me?.username && (
          <div className="hidden text-right sm:block">
            <div className="text-xs font-medium text-gray-200">{me.username.replace(/^apikey:/, "")}</div>
            <div className="text-[10px] uppercase tracking-wider text-gray-500">{me.role}</div>
          </div>
        )}
        <div
          className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-500 text-[13px] font-semibold text-white"
          title={me?.username ? `Signed in as ${me.username}` : "QuantaWatch"}
        >
          {initials}
        </div>
        {me?.authEnabled && me?.username && (
          <button
            onClick={doLogout}
            className="flex h-8 w-8 items-center justify-center rounded-full text-gray-400 hover:bg-white/5 hover:text-white"
            aria-label="Sign out"
            title="Sign out"
          >
            <svg className="h-[18px] w-[18px]" fill="none" viewBox="0 0 24 24" strokeWidth={1.6} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M12 9l-3 3m0 0 3 3m-3-3h12.75" />
            </svg>
          </button>
        )}
      </div>
    </header>
  );
}
