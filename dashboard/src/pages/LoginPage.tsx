import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { login, fetchAuthConfig } from "../api/client";

export default function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { data: authCfg } = useQuery({ queryKey: ["auth-config"], queryFn: fetchAuthConfig });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
      onSuccess();
    } catch {
      setError("Invalid username or password");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded bg-brand-600">
            <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" strokeWidth={2.2} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
            </svg>
          </div>
          <div>
            <h1 className="text-base font-semibold text-white">QuantaWatch</h1>
            <p className="text-[10px] uppercase tracking-wider text-gray-500">Posture Management</p>
          </div>
        </div>

        <form onSubmit={submit} className="qw-card space-y-4 p-6">
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400">Username</label>
            <input
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded border border-white/10 bg-surface-850 px-3 py-2 text-sm text-white outline-none focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/20"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded border border-white/10 bg-surface-850 px-3 py-2 text-sm text-white outline-none focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/20"
            />
          </div>
          {error && <div className="rounded bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</div>}
          <button type="submit" disabled={busy || !username || !password} className="qw-btn-primary w-full">
            {busy ? "Signing in…" : "Sign in"}
          </button>

          {authCfg?.ssoEnabled && (
            <>
              <div className="flex items-center gap-3 text-[11px] text-gray-600">
                <div className="h-px flex-1 bg-white/10" /> or <div className="h-px flex-1 bg-white/10" />
              </div>
              <a href={authCfg.ssoLoginUrl} className="qw-btn-ghost w-full">
                Sign in with SSO
              </a>
            </>
          )}
        </form>
        <p className="mt-4 text-center text-[11px] text-gray-600">Authenticated access · ML-DSA-65 signed audit trail</p>
      </div>
    </div>
  );
}
