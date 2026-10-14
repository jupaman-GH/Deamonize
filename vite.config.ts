import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Tauri expects a fixed port in dev
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    // Multi-page app: index.html (main window) + splash.html (loading window).
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, "index.html"),
        splash: path.resolve(__dirname, "splash.html"),
      },
    },
  },
});
