import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies `/api` to the gateway so the browser talks to a single
// origin and CORS is only exercised in production. In prod the frontend and
// gateway sit behind the same reverse-proxy/nginx config.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://localhost:8094",
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "es2022",
    sourcemap: false,
  },
});
