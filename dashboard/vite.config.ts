import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react(), tailwindcss()],
  // Mantine + React 19: force a single React instance so hooks work (Vite's
  // dep pre-bundling can otherwise load a second copy inside the library chunk).
  resolve: { dedupe: ["react", "react-dom"] },
  optimizeDeps: { include: ["react", "react-dom", "react/jsx-runtime", "@mantine/core", "@mantine/hooks"] },
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:9091",
        changeOrigin: true,
      },
    },
  },
});
