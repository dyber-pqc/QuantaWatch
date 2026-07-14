import { useCallback, useEffect, useState } from "react";
import { fetchMe } from "../api/client";
import LoginPage from "../pages/LoginPage";
import { Spinner } from "./ui";

type Status = "loading" | "ok" | "login";

/** Gates the app behind login when the gateway has auth enabled. */
export default function AuthGate({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");

  const check = useCallback(async () => {
    try {
      const me = await fetchMe();
      // No auth configured, or already authenticated → show the app.
      setStatus(!me.authEnabled || me.authenticated ? "ok" : "login");
    } catch {
      setStatus("login");
    }
  }, []);

  useEffect(() => {
    check();
    const onUnauthorized = () => setStatus("login");
    window.addEventListener("qw-unauthorized", onUnauthorized);
    return () => window.removeEventListener("qw-unauthorized", onUnauthorized);
  }, [check]);

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-950">
        <Spinner />
      </div>
    );
  }
  if (status === "login") {
    return <LoginPage onSuccess={() => setStatus("ok")} />;
  }
  return <>{children}</>;
}
