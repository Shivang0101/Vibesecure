import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Booting the in-memory Postgres (WebAssembly) takes a few seconds.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
