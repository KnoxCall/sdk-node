// Opaque wrapper for sensitive values.
//
// All credentials (access tokens, refresh tokens, client secrets, DPoP
// private keys) flow through this wrapper so accidental logging or error
// serialization can't leak them.

const INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");

export class Redacted<T> {
  #value: T;
  constructor(value: T) {
    this.#value = value;
  }
  expose(): T {
    return this.#value;
  }
  toString(): string {
    return "[REDACTED]";
  }
  toJSON(): string {
    return "[REDACTED]";
  }
  [INSPECT_CUSTOM](): string {
    return "[REDACTED]";
  }
}

export function redact<T>(value: T): Redacted<T> {
  return new Redacted(value);
}
