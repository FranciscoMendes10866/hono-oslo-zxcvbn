import { encodeBase32LowerCaseNoPadding } from "@oslojs/encoding";
import { parse as parseURL } from "tldts";
import { jsonObjectFrom } from "kysely/helpers/sqlite";
import { createMiddleware } from "hono/factory";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";

import { encodeSha256Hex } from "./common";
import { db } from "../db";

export const SESSION_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const RENEW_THRESHOLD_MS = SESSION_EXPIRATION_MS / 2; // 15 days

export function generateRandomToken(entropyBits: number = 160) {
  const bytes = new Uint8Array(entropyBits / 8);
  crypto.getRandomValues(bytes);
  return encodeBase32LowerCaseNoPadding(bytes);
}

export const COOKIE_OPTIONS = Object.freeze(
  (() => {
    const url = new URL(process.env.FRONTEND_DOMAIN_URL || "");
    return {
      domain: parseURL(url.toString()).domain || undefined,
      secure: url.protocol.startsWith("https"),
      sameSite: "lax" as const,
      httpOnly: true,
      path: "/",
    };
  })(),
);

export const STATIC_SESSION_SCOPE = {
  AUTH: "AUTH",
  FORGOT_PASSWORD: "FORGOT_PASSWORD",
} as const;

export const EMAIL_VERIFICATION_FLAGS = {
  VERIFIED: 1,
  UNVERIFIED: 0,
} as const;

export type SessionDatum = {
  id: string;
  expiresAt: Date;
  userId: string;
  isVerified: boolean;
  scope: keyof typeof STATIC_SESSION_SCOPE;
};

export const EMPTY_SESSION = Object.freeze({
  id: null,
  expiresAt: null,
  userId: null,
  isVerified: false,
  scope: null,
});

export async function resolveSession(token: string | null): Promise<
  | {
      type: "NO_SESSION";
      payload: typeof EMPTY_SESSION;
    }
  | {
      type: "SESSION_ACTIVE";
      payload: SessionDatum;
    }
  | {
      type: "SESSION_EXTENDED";
      payload: SessionDatum;
    }
> {
  if (!token) return { type: "NO_SESSION", payload: EMPTY_SESSION };

  const sessionId = encodeSha256Hex(token);

  const session = await db
    .selectFrom("userSessions")
    .select((eb) => [
      "id",
      "expiresAt",
      "userId",
      jsonObjectFrom(
        eb
          .selectFrom("users")
          .select(["users.emailVerified"])
          .whereRef("users.id", "=", "userSessions.userId"),
      )
        .$notNull()
        .as("user"),
    ])
    .where("id", "=", sessionId)
    .executeTakeFirst();
  if (!session) return { type: "NO_SESSION", payload: EMPTY_SESSION };

  const clonedSession = structuredClone(session);
  const now = Date.now();

  const isExpired = now >= clonedSession.expiresAt;
  if (isExpired) {
    try {
      await db
        .deleteFrom("userSessions")
        .where("id", "=", sessionId)
        .executeTakeFirstOrThrow();
    } catch {
      // silent error
    } finally {
      return { type: "NO_SESSION", payload: EMPTY_SESSION };
    }
  }

  const needsRenewal = now >= clonedSession.expiresAt - RENEW_THRESHOLD_MS;
  if (needsRenewal) {
    const expiration = now + SESSION_EXPIRATION_MS;
    const updatedSession = await db
      .updateTable("userSessions")
      .set({ expiresAt: expiration })
      .where("id", "=", sessionId)
      .returning("expiresAt")
      .executeTakeFirst();
    if (!updatedSession) return { type: "NO_SESSION", payload: EMPTY_SESSION };
    clonedSession.expiresAt = updatedSession.expiresAt;
  }

  return {
    type:
      session.expiresAt === clonedSession.expiresAt
        ? "SESSION_ACTIVE"
        : "SESSION_EXTENDED",
    payload: {
      id: sessionId,
      expiresAt: new Date(clonedSession.expiresAt),
      isVerified:
        clonedSession.user.emailVerified === EMAIL_VERIFICATION_FLAGS.VERIFIED,
      userId: clonedSession.userId,
      scope: STATIC_SESSION_SCOPE.AUTH, // TODO
    },
  };
}

export type HonoGlobalContext = {
  Variables: { userSession: typeof EMPTY_SESSION | SessionDatum };
};

export const sessionMiddleware = createMiddleware<HonoGlobalContext>(
  async (c, next) => {
    const sessionToken = getCookie(c, "session") || null;

    const { type, payload } = await resolveSession(sessionToken);

    if (sessionToken && type === "NO_SESSION") {
      deleteCookie(c, "session");
    }

    if (sessionToken && type === "SESSION_EXTENDED") {
      setCookie(c, "session", sessionToken, {
        ...COOKIE_OPTIONS,
        expires: payload.expiresAt,
      });
    }

    c.set("userSession", payload);
    await next();
  },
);

export const guardWithUserAuth = createMiddleware<HonoGlobalContext>(
  async (c, next) => {
    const datum = c.get("userSession");
    if (!datum.userId || !datum.id) throw new HTTPException(401);
    await next();
  },
);

export const enforceEmailVerification = createMiddleware<HonoGlobalContext>(
  async (c, next) => {
    const datum = c.get("userSession");
    if (!datum.isVerified) throw new HTTPException(403);
    await next();
  },
);
