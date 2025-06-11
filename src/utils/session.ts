import { encodeBase32LowerCaseNoPadding } from "@oslojs/encoding";
import { parse as parseURL } from "tldts";

export const SESSION_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 30; // 30 days

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

export const COOKIE_OPTIONS = Object.freeze(generateCookieDefaults());

export const STATIC_SESSION_SCOPE = {
  AUTH: "AUTH",
  FORGOT_PASSWORD: "FORGOT_PASSWORD",
} as const;

export type SessionDatum = {
  id: string | null;
  expiresAt: Date | null;
  userId: string | null;
  isVerified: boolean;
  scope: keyof typeof STATIC_SESSION_SCOPE | null;
};

export const EMPTY_SESSION = Object.freeze({
  id: null,
  expiresAt: null,
  userId: null,
  isVerified: false,
  scope: null,
} satisfies SessionDatum);
