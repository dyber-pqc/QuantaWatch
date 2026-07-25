import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import QRCode from "qrcode";
import {
  login,
  setupAdmin,
  enrollBegin,
  enrollConfirm,
  verify2fa,
  fetchAuthConfig,
  fetchAuthStatus,
} from "../api/client";

type Phase = "login" | "setup" | "enroll" | "totp" | "backup";

const inputCls =
  "w-full rounded border border-white/10 bg-surface-850 px-3 py-2 text-sm text-white outline-none focus:border-brand-500/60 focus:ring-2 focus:ring-brand-500/20";

/** Full auth flow: first-run setup, login, mandatory TOTP enrollment, the
 * second-factor step, and one-time backup codes. */
export default function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const { data: authCfg } = useQuery({ queryKey: ["auth-config"], queryFn: fetchAuthConfig });
  const { data: status } = useQuery({ queryKey: ["auth-status"], queryFn: fetchAuthStatus });

  const [phase, setPhase] = useState<Phase>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState("");
  const [secret, setSecret] = useState("");
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Fresh install → show the setup wizard instead of the login form.
  useEffect(() => {
    if (status?.setupRequired) setPhase("setup");
  }, [status?.setupRequired]);

  // Render the otpauth URL as a QR whenever we enter enrollment.
  const startEnroll = async (p: string) => {
    const info = await enrollBegin(p);
    setSecret(info.secret);
    setPending(info.pending);
    setQr(await QRCode.toDataURL(info.otpauthUrl, { margin: 1, width: 200 }).catch(() => ""));
    setPhase("enroll");
  };

  const doLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const step = await login(username, password);
      if (step.kind === "ok") onSuccess();
      else if (step.kind === "totp") {
        setPending(step.pending);
        setPhase("totp");
      } else await startEnroll(step.pending);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  const doSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { pending: p } = await setupAdmin(username, password);
      await startEnroll(p);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setBusy(false);
    }
  };

  const doConfirmEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const codes = await enrollConfirm(pending, code);
      setBackupCodes(codes);
      setCode("");
      setPhase("backup");
    } catch {
      // The pending is single-use; re-prime with the same secret so the QR the
      // user already scanned stays valid, then let them retry.
      setError("That code didn't match. Check your device clock and try again.");
      setCode("");
      try {
        const step = await login(username, password);
        if (step.kind === "enroll") await startEnroll(step.pending);
      } catch {
        setError("Session expired — please start over.");
        setPhase("login");
      }
    } finally {
      setBusy(false);
    }
  };

  const doVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verify2fa(pending, code);
      onSuccess();
    } catch {
      setError("Invalid or expired code. Enter the current code (or a backup code).");
      setCode("");
      // Re-issue a fresh pending for the next attempt.
      try {
        const step = await login(username, password);
        if (step.kind === "totp") setPending(step.pending);
      } catch {
        setPhase("login");
      }
    } finally {
      setBusy(false);
    }
  };

  const restart = () => {
    setPhase(status?.setupRequired ? "setup" : "login");
    setPassword("");
    setPending("");
    setCode("");
    setError(null);
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

        {/* ---- Login ---- */}
        {phase === "login" && (
          <form onSubmit={doLogin} className="qw-card space-y-4 p-6">
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">Username</label>
              <input autoFocus value={username} onChange={(e) => setUsername(e.target.value)} className={inputCls} />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} />
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
        )}

        {/* ---- First-run setup ---- */}
        {phase === "setup" && (
          <form onSubmit={doSetup} className="qw-card space-y-4 p-6">
            <div>
              <h2 className="text-sm font-semibold text-white">Create your admin account</h2>
              <p className="mt-1 text-[11px] text-gray-500">
                First-run setup for this install. You'll set up two-factor authentication next.
              </p>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">Username</label>
              <input autoFocus value={username} onChange={(e) => setUsername(e.target.value)} className={inputCls} />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} />
              <p className="mt-1 text-[10px] text-gray-600">At least 12 characters.</p>
            </div>
            {error && <div className="rounded bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</div>}
            <button
              type="submit"
              disabled={busy || !username || password.length < 12}
              className="qw-btn-primary w-full"
            >
              {busy ? "Creating…" : "Create admin & continue"}
            </button>
          </form>
        )}

        {/* ---- 2FA enrollment ---- */}
        {phase === "enroll" && (
          <form onSubmit={doConfirmEnroll} className="qw-card space-y-4 p-6">
            <div>
              <h2 className="text-sm font-semibold text-white">Set up two-factor authentication</h2>
              <p className="mt-1 text-[11px] text-gray-500">
                Scan this with an authenticator app (or enter the key manually), then enter the 6-digit code.
              </p>
            </div>
            {qr && (
              <div className="flex justify-center">
                <img src={qr} alt="TOTP QR code" className="rounded bg-white p-2" width={180} height={180} />
              </div>
            )}
            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-gray-500">Manual entry key</label>
              <code className="block break-all rounded bg-surface-850 px-2 py-1.5 font-mono text-[11px] text-brand-300">
                {secret}
              </code>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">6-digit code</label>
              <input
                autoFocus
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                className={`${inputCls} text-center font-mono tracking-[0.3em]`}
              />
            </div>
            {error && <div className="rounded bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</div>}
            <button type="submit" disabled={busy || code.length !== 6} className="qw-btn-primary w-full">
              {busy ? "Verifying…" : "Verify & enable"}
            </button>
          </form>
        )}

        {/* ---- Second-factor login step ---- */}
        {phase === "totp" && (
          <form onSubmit={doVerify} className="qw-card space-y-4 p-6">
            <div>
              <h2 className="text-sm font-semibold text-white">Two-factor authentication</h2>
              <p className="mt-1 text-[11px] text-gray-500">Enter the current code from your authenticator app.</p>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">Code</label>
              <input
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9a-zA-Z-]/g, "").slice(0, 16))}
                placeholder="6-digit or backup code"
                className={`${inputCls} text-center font-mono tracking-[0.2em]`}
              />
            </div>
            {error && <div className="rounded bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</div>}
            <button type="submit" disabled={busy || code.length < 6} className="qw-btn-primary w-full">
              {busy ? "Verifying…" : "Verify"}
            </button>
            <button type="button" onClick={restart} className="qw-btn-ghost w-full">
              Back to sign in
            </button>
          </form>
        )}

        {/* ---- Backup codes (shown once) ---- */}
        {phase === "backup" && (
          <div className="qw-card space-y-4 p-6">
            <div>
              <h2 className="text-sm font-semibold text-white">Save your backup codes</h2>
              <p className="mt-1 text-[11px] text-gray-500">
                Each code works once if you lose your authenticator. Store them somewhere safe — they won't be shown
                again.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-1.5 rounded bg-surface-850 p-3">
              {backupCodes.map((c) => (
                <code key={c} className="font-mono text-[12px] text-brand-300">
                  {c}
                </code>
              ))}
            </div>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(backupCodes.join("\n")).catch(() => {})}
              className="qw-btn-ghost w-full"
            >
              Copy codes
            </button>
            <button type="button" onClick={onSuccess} className="qw-btn-primary w-full">
              I've saved them — continue
            </button>
          </div>
        )}

        <p className="mt-4 text-center text-[11px] text-gray-600">
          Authenticated access · ML-DSA-65 signed audit trail
        </p>
      </div>
    </div>
  );
}
