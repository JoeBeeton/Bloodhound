import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Lets `npm run dev` talk to webui's backend (which proxies auth to
      // central-server) without CORS, mirroring the same-origin setup the
      // production image gets for free by serving both from one container.
      "/api": {
        target: process.env.VITE_PROXY_TARGET ?? "http://localhost:8090",
        changeOrigin: true,
      },
    },
  },
});
