// DPoP proof generation (RFC 9449) — client side.
//
// Generates an ES256 keypair on construction, signs a fresh proof JWT
// per request. The private key is held as a KeyObject so it never reaches
// V8 string heap.

import {
  createSign,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from "crypto";

function b64url(buf: Buffer | string): string {
  const b = typeof buf === "string" ? Buffer.from(buf, "utf8") : buf;
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlJson(obj: unknown): string {
  return b64url(Buffer.from(JSON.stringify(obj), "utf8"));
}

function derToP1363(der: Buffer): Buffer {
  if (der[0] !== 0x30) throw new Error("invalid DER signature");
  let i = 2;
  if (der[i] !== 0x02) throw new Error("invalid DER signature");
  const lenR = der[i + 1];
  let r = der.subarray(i + 2, i + 2 + lenR);
  i = i + 2 + lenR;
  if (der[i] !== 0x02) throw new Error("invalid DER signature");
  const lenS = der[i + 1];
  let s = der.subarray(i + 2, i + 2 + lenS);
  while (r.length > 32 && r[0] === 0) r = r.subarray(1);
  while (s.length > 32 && s[0] === 0) s = s.subarray(1);
  if (r.length < 32) r = Buffer.concat([Buffer.alloc(32 - r.length, 0), r]);
  if (s.length < 32) s = Buffer.concat([Buffer.alloc(32 - s.length, 0), s]);
  return Buffer.concat([r, s]);
}

export interface DpopJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
}

export class DpopKeyPair {
  readonly publicJwk: DpopJwk;
  readonly #privateKey: KeyObject;

  private constructor(privateKey: KeyObject, publicJwk: DpopJwk) {
    this.#privateKey = privateKey;
    this.publicJwk = publicJwk;
  }

  /** Generate a fresh ES256 keypair. Private key never leaves this object. */
  static generate(): DpopKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as DpopJwk;
    return new DpopKeyPair(privateKey, { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
  }

  /** Sign a DPoP proof JWT for a specific request (RFC 9449 §4.2). */
  sign(opts: { method: string; url: string; accessToken?: string; nonce?: string }): string {
    const header = { alg: "ES256", typ: "dpop+jwt", jwk: this.publicJwk };
    const payload: Record<string, unknown> = {
      htm: opts.method.toUpperCase(),
      htu: opts.url.split("#")[0].split("?")[0],
      iat: Math.floor(Date.now() / 1000),
      jti: b64url(randomBytes(16)),
    };
    if (opts.accessToken) {
      payload.ath = b64url(createHash("sha256").update(opts.accessToken).digest());
    }
    if (opts.nonce) payload.nonce = opts.nonce;
    const headerB64 = b64urlJson(header);
    const payloadB64 = b64urlJson(payload);
    const signingInput = `${headerB64}.${payloadB64}`;
    const signer = createSign("SHA256");
    signer.update(signingInput);
    signer.end();
    const der = signer.sign(this.#privateKey);
    return `${signingInput}.${b64url(derToP1363(der))}`;
  }

  /** RFC 7638 thumbprint for the public key — used as cnf.jkt in tokens. */
  thumbprint(): string {
    if (this.publicJwk.kty !== "EC" || this.publicJwk.crv !== "P-256" || !this.publicJwk.x || !this.publicJwk.y) {
      throw new Error("only EC P-256 supported");
    }
    const canonical = JSON.stringify({
      crv: this.publicJwk.crv,
      kty: this.publicJwk.kty,
      x: this.publicJwk.x,
      y: this.publicJwk.y,
    });
    return b64url(createHash("sha256").update(canonical).digest());
  }
}
