import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MantineProvider } from "@mantine/core";
import "@mantine/core/styles.css";
import "@fontsource-variable/public-sans";
import "@fontsource/cascadia-code/400.css";
import "@fontsource/cascadia-code/600.css";
import App from "./App";
import AuthGate from "./components/AuthGate";
import { setToken } from "./api/client";
import { theme } from "./theme";
import "./index.css";

// SSO callback: the gateway redirects here with ?sso=<session token>.
const ssoToken = new URLSearchParams(window.location.search).get("sso");
if (ssoToken) {
  setToken(ssoToken);
  const url = new URL(window.location.href);
  url.searchParams.delete("sso");
  window.history.replaceState({}, "", url.toString());
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 15_000,
      retry: 1,
      staleTime: 10_000,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={theme} forceColorScheme="dark">
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthGate>
            <App />
          </AuthGate>
        </BrowserRouter>
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
