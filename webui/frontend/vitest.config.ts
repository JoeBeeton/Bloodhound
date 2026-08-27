import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/** Separate from vite.config.ts (which is the dev-server/build config) so `vitest` never picks up the dev proxy settings. */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The default 5000ms is too tight in this sandbox - jsdom environment setup alone has been
    // observed taking 15-20s+ here, well beyond a typical dev machine, so a multi-step test
    // (user interaction + a query refetch) can trip the ambient per-test timeout even though
    // nothing is actually hung.
    testTimeout: 20000,
  },
});
