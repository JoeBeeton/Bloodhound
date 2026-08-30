import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Vite inlines small assets (<4KB) as base64 data: URIs by default. That's
    // fine for images (CSP's img-src already allows data:), but font-src does
    // not - confirmed live via a real CSP violation ("font-src 'self'" blocked
    // a data: URI) once @fontsource's smallest woff2 subset files got inlined.
    // Excluding fonts keeps every font a same-origin hashed file, which needs
    // no CSP change and caches better than a data URI baked into the CSS bundle.
    assetsInlineLimit: (filePath) => (/\.(woff2?|ttf|otf|eot)$/i.test(filePath) ? false : undefined),
  },
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
