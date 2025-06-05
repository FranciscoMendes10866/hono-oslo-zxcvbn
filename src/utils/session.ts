import { encodeBase32LowerCaseNoPadding } from "@oslojs/encoding";
import { parse as parseURL } from "tldts";

export function generateRandomToken(entropyBits: number = 160) {
  const bytes = new Uint8Array(entropyBits / 8);
  crypto.getRandomValues(bytes);
  return encodeBase32LowerCaseNoPadding(bytes);
}

export function generateCookieDefaults() {
  const url = new URL(process.env.FRONTEND_DOMAIN_URL || "");
  return {
    domain: parseURL(url.toString()).domain || undefined,
    secure: url.protocol.startsWith("https"),
    sameSite: "lax" as const,
    httpOnly: true,
    path: "/",
  };
}
