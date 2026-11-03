// Browser DPoP via WebCrypto with non-extractable keys.
//
// Differs from the Node version (src/auth/dpop.ts):
//   - Keypair generated with extractable: false — JS can't read the
//     private key, so XSS / supply-chain attacks can't exfiltrate it
//   - Stored in IndexedDB as a CryptoKey reference (not as PEM/JWK
//     material), so even getting the DB contents reveals no usable
//     private material
//   - Uses async crypto.subtle calls throughout

const B64URL_PAD_RE = /=+$/;

function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < arr.byteLength; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(B64URL_PAD_RE, "");
}

function b64urlEncodeJson(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

export interface BrowserDpopJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
}

/**
 * Browser-side DPoP keypair. The private key is non-extractable — the
 * JS heap never sees it. The keypair survives a page reload via
 * IndexedDB; call `BrowserDpopKeyPair.load()` to restore it.
 */
export class BrowserDpopKeyPair {
  readonly publicJwk: BrowserDpopJwk;
  readonly #privateKey: CryptoKey;
  readonly #publicKey: CryptoKey;

  private constructor(privateKey: CryptoKey, publicKey: CryptoKey, publicJwk: BrowserDpopJwk) {
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
    this.publicJwk = publicJwk;
  }

  /** Generate a fresh non-extractable ES256 keypair. */
  static async generate(): Promise<BrowserDpopKeyPair> {
    const kp = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // non-extractable!
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
    return new BrowserDpopKeyPair(kp.privateKey, kp.publicKey, {
      kty: jwk.kty ?? "EC",
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    });
  }

  /** Sign a DPoP proof JWT for one specific request. */
  async sign(opts: { method: string; url: string; accessToken?: string; nonce?: string }): Promise<string> {
    const header = { alg: "ES256", typ: "dpop+jwt", jwk: this.publicJwk };
    const cleanUrl = opts.url.split("#")[0].split("?")[0];
    const payload: Record<string, unknown> = {
      htm: opts.method.toUpperCase(),
      htu: cleanUrl,
      iat: Math.floor(Date.now() / 1000),
      jti: b64urlEncode(crypto.getRandomValues(new Uint8Array(16))),
    };
    if (opts.accessToken) {
      const ath = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(opts.accessToken));
      payload.ath = b64urlEncode(ath);
    }
    if (opts.nonce) payload.nonce = opts.nonce;

    const headerB64 = b64urlEncodeJson(header);
    const payloadB64 = b64urlEncodeJson(payload);
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    // ECDSA over SHA-256 — WebCrypto returns r||s already (P1363) so we
    // can b64url-encode directly. The Node SDK does DER→P1363 manually;
    // the browser is easier.
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      this.#privateKey,
      signingInput,
    );
    return `${headerB64}.${payloadB64}.${b64urlEncode(sig)}`;
  }

  /** RFC 7638 thumbprint — used as cnf.jkt on issued tokens. */
  async thumbprint(): Promise<string> {
    if (this.publicJwk.kty !== "EC" || this.publicJwk.crv !== "P-256" || !this.publicJwk.x || !this.publicJwk.y) {
      throw new Error("only EC P-256 supported");
    }
    const canonical = JSON.stringify({
      crv: this.publicJwk.crv,
      kty: this.publicJwk.kty,
      x: this.publicJwk.x,
      y: this.publicJwk.y,
    });
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return b64urlEncode(digest);
  }

  /** Persist the keypair reference to IndexedDB so it survives reloads. */
  async persist(dbName = "knoxcall", storeName = "dpop"): Promise<void> {
    const db = await openDb(dbName, storeName);
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const req = tx.objectStore(storeName).put(
        { privateKey: this.#privateKey, publicKey: this.#publicKey, publicJwk: this.publicJwk },
        "default",
      );
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
    db.close();
  }

  /** Restore a previously-persisted keypair, or null if none exists. */
  static async load(dbName = "knoxcall", storeName = "dpop"): Promise<BrowserDpopKeyPair | null> {
    const db = await openDb(dbName, storeName);
    return new Promise<BrowserDpopKeyPair | null>((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const req = tx.objectStore(storeName).get("default");
      req.onsuccess = () => {
        const v = req.result as
          | { privateKey: CryptoKey; publicKey: CryptoKey; publicJwk: BrowserDpopJwk }
          | undefined;
        db.close();
        if (!v) return resolve(null);
        resolve(new BrowserDpopKeyPair(v.privateKey, v.publicKey, v.publicJwk));
      };
      req.onerror = () => {
        db.close();
        reject(req.error);
      };
    });
  }
}

function openDb(dbName: string, storeName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
