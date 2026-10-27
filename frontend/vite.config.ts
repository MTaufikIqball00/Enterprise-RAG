import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend port is configurable via BACKEND_PORT (set by start_enterprise_rag.bat).
// Default 8010: port 8000 on this machine is reserved by a Windows netsh portproxy rule.
const backendPort = process.env.BACKEND_PORT || "8010";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
    },
  },
});
