import {defineConfig} from "vitest/config"

// The integration suites cold-spawn up to 8 signer processes in each
// `beforeEach` via `setupSuite` -> `spawnSigners` -> `waitForPort`. The harness
// allows each signer up to 15s to bind its port (see packages/tests/harness.ts),
// so the enclosing vitest hook budget must comfortably exceed that 15s deadline.
// Vitest's defaults (hookTimeout 10s, testTimeout 5s) are shorter than the
// harness's own startup deadline, which made the hook abort before a slow
// signer could ever finish coming up. Bump both well past 15s to remove the
// flaky "Hook timed out in 10000ms" failures on loaded/cold machines.
export default defineConfig({
  test: {
    hookTimeout: 30_000,
    testTimeout: 30_000,
  },
})
