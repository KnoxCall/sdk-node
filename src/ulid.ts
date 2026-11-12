// ULID generator for idempotency keys.
//
// 128-bit value: 48 bits of millisecond time + 80 bits of randomness,
// encoded as 26 chars of Crockford base32. Sortable by time, debuggable.
// Spec: https://github.com/ulid/spec

import { randomBytes } from "crypto";

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(now: number = Date.now()): string {
  // Time portion: 48 bits = 10 chars in b32
  let time = now;
  let timePart = "";
  for (let i = 9; i >= 0; i--) {
    const mod = time % 32;
    timePart = B32[mod] + timePart;
    time = (time - mod) / 32;
  }

  // Random portion: 80 bits = 16 chars in b32
  const rand = randomBytes(10);
  let randPart = "";
  let bitBuffer = 0;
  let bitsInBuffer = 0;
  for (const byte of rand) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitsInBuffer += 8;
    while (bitsInBuffer >= 5) {
      bitsInBuffer -= 5;
      randPart += B32[(bitBuffer >> bitsInBuffer) & 0x1f];
    }
  }
  if (bitsInBuffer > 0) {
    randPart += B32[(bitBuffer << (5 - bitsInBuffer)) & 0x1f];
  }
  return (timePart + randPart).slice(0, 26);
}
