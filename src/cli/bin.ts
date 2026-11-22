#!/usr/bin/env node
// `knoxcall` executable — thin wrapper; all logic lives in main() for
// testability. Interrupt (Ctrl+C) prints `aborted` and exits 1, matching
// the python reference's KeyboardInterrupt handling (PARITY §13).

import { main } from "./main.js";

process.on("SIGINT", () => {
  console.error("aborted");
  process.exit(1);
});

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  // Unexpected failure — surface it (expected ones are handled in main()).
  console.error(err);
  process.exitCode = 1;
}
