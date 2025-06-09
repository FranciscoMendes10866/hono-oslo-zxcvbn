import { Hono } from "hono";
import { cors } from "hono/cors";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";
import { setCookie } from "hono/cookie";
import { serve } from "@hono/node-server";

import {
  signUpBodySchema,
  requestEmailVerificationParamsSchema,
  requestEmailVerificationQuerySchema,
  requestEmailUpdateBodySchema,
} from "./schemas";
import {
  isPasswordGuessable,
  hash,
  encodeSha256Hex,
  verifyHash,
} from "./utils/common";
import {
  generateCookieDefaults,
  generateRandomToken,
  SESSION_EXPIRATION_MS,
} from "./utils/session";
import { db } from "./db";

const COOKIE_OPTIONS = Object.freeze(generateCookieDefaults());

// TODO: add bot protection to the (send) password reset email route [isbot npm package]

const app = new Hono()
  .basePath("/api")
  .use(
    cors({
      credentials: true,
      origin: process.env.FRONTEND_DOMAIN_URL || "*",
    }),
  )
  .post("/users", validator("json", signUpBodySchema.parse), async (c) => {
    const body = c.req.valid("json");

    let password = body.password.trim();

    if (password !== body.confirmPassword.trim()) {
      throw new HTTPException(400);
    }

    if (isPasswordGuessable(password)) {
      throw new HTTPException(400, { message: "Weak password" });
    }

    const result = await db
      .selectFrom("users")
      .select("id")
      .where("email", "=", body.email)
      .executeTakeFirst();

    if (typeof result?.id === "string") {
      throw new HTTPException(409);
    }

    password = hash(password);

    const datums = await db.transaction().execute(async (trx) => {
      const user = await trx
        .insertInto("users")
        .values({
          email: body.email,
          username: body.username,
          passwordHash: password,
        })
        .returning("id")
        .executeTakeFirstOrThrow();

      const sessionToken = generateRandomToken();
      const expiration = new Date(Date.now() + SESSION_EXPIRATION_MS);

      await trx
        .insertInto("userSessions")
        .values({
          id: encodeSha256Hex(sessionToken),
          userId: user.id!,
          expiresAt: expiration.getTime(),
        })
        .executeTakeFirstOrThrow();

      return { sessionToken, expiration };
    });

    setCookie(c, "session", datums.sessionToken, {
      ...COOKIE_OPTIONS,
      expires: datums.expiration,
    });

    return c.json(
      {
        success: true,
        error: null,
        content: null,
      } satisfies JSONResponseBase,
      201,
    );
  })
  .post(
    "/users/:userId/email-verification-request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself

      // TODO: rate limit to max 1 request in a 10min window (by userId and not IP)

      const codeVerifier = generateRandomToken(40);

      const datums = {
        userId,
        expiresAt: Date.now() + 10 * 60 * 1_000, // 10min
        codeChallenge: hash(codeVerifier),
      };

      await db
        .insertInto("emailVerificationRequests")
        .values(datums)
        .onConflict((oc) =>
          oc.column("userId").doUpdateSet(() => ({
            createdAt: Date.now(),
            expiresAt: datums.expiresAt,
            codeChallenge: datums.codeChallenge,
          })),
        )
        .executeTakeFirstOrThrow();

      // TODO: send email with code verifier

      return c.json(
        {
          success: true,
          error: null,
          content: null,
        } satisfies JSONResponseBase,
        201,
      );
    },
  )
  .get(
    "/users/:userId/email-verification-request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    validator("query", requestEmailVerificationQuerySchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const queryParams = c.req.valid("query");

      // TODO: rate limit to max 5 requests in a 5min window (by userId and not IP)

      const result = await db
        .selectFrom("emailVerificationRequests")
        .where("userId", "==", userId)
        .select(["expiresAt as expiration", "codeChallenge"])
        .executeTakeFirst();

      if (typeof result === "undefined") {
        throw new HTTPException(404);
      }

      if (Date.now() >= result.expiration) {
        await db
          .deleteFrom("emailVerificationRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();

        throw new HTTPException(403);
      }

      const isValidCode = verifyHash(result.codeChallenge, queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      await db.transaction().execute(async (tx) => {
        await tx
          .updateTable("users")
          .where("id", "=", userId)
          .set({ emailVerified: 1 }) // set the user email as verified
          .executeTakeFirstOrThrow();

        await tx
          .deleteFrom("emailVerificationRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();
      });

      return c.json(
        {
          success: true,
          error: null,
          content: null,
        } satisfies JSONResponseBase,
        200,
      );
    },
  )
  .post(
    "/users/:userId/email-update-request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    validator("json", requestEmailUpdateBodySchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const { newEmail } = c.req.valid("json");

      // TODO: verify the session datum assigned to the http request to check if the account is verified

      // TODO: rate limit to max 1 request in a 10min window (by userId and not IP)

      const codeVerifier = generateRandomToken(40);

      const datums = {
        userId,
        expiresAt: Date.now() + 10 * 60 * 1_000, // 10min
        codeChallenge: hash(codeVerifier),
        newEmail,
      };

      await db
        .insertInto("emailUpdateRequests")
        .values(datums)
        .onConflict((oc) =>
          oc.column("userId").doUpdateSet(() => ({
            createdAt: Date.now(),
            expiresAt: datums.expiresAt,
            codeChallenge: datums.codeChallenge,
          })),
        )
        .executeTakeFirstOrThrow();

      // TODO: send email with code verifier

      return c.json(
        {
          success: true,
          error: null,
          content: null,
        } satisfies JSONResponseBase,
        201,
      );
    },
  )
  .get(
    "/users/:userId/email-update-request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    validator("query", requestEmailVerificationQuerySchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const queryParams = c.req.valid("query");

      // TODO: rate limit to max 5 requests in a 5min window (by userId and not IP)

      const result = await db
        .selectFrom("emailUpdateRequests")
        .select(["expiresAt as expiration", "codeChallenge", "newEmail"])
        .where("userId", "=", "<=")
        .executeTakeFirst();

      if (typeof result === "undefined") {
        throw new HTTPException(404);
      }

      if (Date.now() >= result.expiration) {
        await db
          .deleteFrom("emailUpdateRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();

        throw new HTTPException(404);
      }

      const isValidCode = verifyHash(result.codeChallenge, queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      await db.transaction().execute(async (tx) => {
        await tx
          .updateTable("users")
          .where("id", "=", userId)
          .set({ email: result.newEmail })
          .executeTakeFirstOrThrow();

        await tx
          .deleteFrom("emailUpdateRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();

        await tx
          .deleteFrom("passwordResetRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();
      });

      return c.json(
        {
          success: true,
          error: null,
          content: null,
        } satisfies JSONResponseBase,
        200,
      );
    },
  );

serve({ port: 3333, fetch: app.fetch });
