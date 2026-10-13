// Browser entrypoint for @knoxcall/sdk.
//
// Browser callers have a different threat model: no FileTokenStore, no
// env-var bootstrap, no client_credentials (browser code can't safely
// hold a client secret). The recommended browser pattern is BFF — your
// own backend holds the OAuth client and proxies API calls. This
// entrypoint is for SPAs that must call KnoxCall directly (rare).
//
//   import { KnoxCallBrowser } from "@knoxcall/sdk/browser";
//   const client = new KnoxCallBrowser({ tenant: "acme", accessToken: "kc_live_..." });
//   await client.routes.list();

export { BrowserDpopKeyPair, type BrowserDpopJwk } from "./dpop.js";

// We do not re-export the Node-only modules (FileTokenStore, RedisTokenStore,
// MemoryTokenStore that uses crypto.generateKeyPairSync, etc.) from the
// browser entrypoint to keep the browser bundle small and free of Node
// shims. A browser-friendly TokenStore + client class would be next here
// when SPA callers materialise — see the README for the BFF pattern in
// the meantime.
