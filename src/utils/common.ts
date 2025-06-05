import { hashSync, verifySync } from "@node-rs/argon2";
import { sha256 } from "@oslojs/crypto/sha2";
import { encodeHexLowerCase } from "@oslojs/encoding";
import { zxcvbn } from "@zxcvbn-ts/core";

export function hash(value: string) {
  return hashSync(value, {
    memoryCost: 19_456,
    timeCost: 2,
    outputLen: 32,
    parallelism: 1,
  });
}

export function verifyHash(hash: string, value: string) {
  return verifySync(hash, value);
}

export function encodeSha256Hex(input: string) {
  const value = new TextEncoder().encode(input);
  return encodeHexLowerCase(sha256(value));
}

export function isPasswordGuessable(password: string) {
  return zxcvbn(password).score < 3;
}
