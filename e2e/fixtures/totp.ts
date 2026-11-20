// Codes de vérification à usage unique (RFC 6238, TOTP) calculés avec
// node:crypto, sans dépendance : pour les tests de double authentification.

import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Décode une clé en base32 (RFC 4648), espaces et « = » tolérés. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`Caractère base32 invalide : ${ch}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export interface TotpOptions {
  /** Instant en secondes Unix (défaut : maintenant). */
  time?: number;
  step?: number;
  digits?: number;
  algorithm?: "sha1" | "sha256" | "sha512";
}

/** Code TOTP pour une clé base32 ou un lien otpauth://. */
export function totp(secret: string, { time = Date.now() / 1000, step = 30, digits = 6, algorithm = "sha1" }: TotpOptions = {}): string {
  let key = secret;
  if (secret.startsWith("otpauth://")) {
    const url = new URL(secret);
    key = url.searchParams.get("secret") || "";
    step = Number(url.searchParams.get("period")) || step;
    digits = Number(url.searchParams.get("digits")) || digits;
    algorithm = (url.searchParams.get("algorithm")?.toLowerCase() as TotpOptions["algorithm"]) || algorithm;
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / step)));
  const mac = createHmac(algorithm, base32Decode(key)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

/** Secondes restantes avant le prochain code (pour éviter de saisir un code expirant). */
export const secondsLeft = (step = 30, time = Date.now() / 1000) => step - (Math.floor(time) % step);
