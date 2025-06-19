import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";
import { setCookie } from "hono/cookie";

import {
  requestResetPasswordBodySchema,
  resetPasswordBodySchema,
  verifyResetPasswordParamsSchema,
} from "../schemas";
import {
  encodeSha256Hex,
  hash,
  isPasswordGuessable,
  normalizeEmail,
  verifyHash,
} from "../utils/common";
import {
  COOKIE_OPTIONS,
  generateRandomToken,
  guardWithUserAuth,
  SESSION_EXPIRATION_MS,
  STATIC_SESSION_SCOPE,
} from "../utils/session";
import { db } from "../db";

export const passwordReset = new Hono()
  .post(
    "/:userId/request",
    validator("json", requestResetPasswordBodySchema.parse),
    async (c) => {
      const { email } = c.req.valid("json");

      // TODO: rate limit to max 1 request in a 10min window (by userId and not IP)

      const normalizedEmail = normalizeEmail(email);
      if (!normalizedEmail) throw new HTTPException(400);

      const result = await db
        .selectFrom("users")
        .select("id")
        .where("email", "=", normalizedEmail)
        .executeTakeFirst();
      if (!result?.id) throw new HTTPException(404);

      await db
        .deleteFrom("passwordResetRequests")
        .where((eb) =>
          eb.and([
            eb("userId", "=", result.id),
            eb("expiresAt", "<=", Date.now()),
          ]),
        )
        .execute();

      const codeVerifier = generateRandomToken(40);

      const datums = {
        userId: result.id,
        expiresAt: Date.now() + 10 * 60 * 1_000, // 10min
        codeChallenge: hash(codeVerifier),
      };

      const transactionResult = await db.transaction().execute(async (trx) => {
        const sessionToken = generateRandomToken();
        const sessionId = encodeSha256Hex(sessionToken);

        await trx
          .insertInto("userSessions")
          .values({
            id: sessionId,
            userId: datums.userId,
            expiresAt: datums.expiresAt,
            scope: STATIC_SESSION_SCOPE.FORGOT_PASSWORD,
          })
          .executeTakeFirstOrThrow();

        // TODO: maybe assign a sessionId to the password_reset_requests table with cascade
        // → when password_reset_request gets deleted the corresponding session gets deleted as well
        await trx
          .insertInto("passwordResetRequests")
          .values(datums)
          .onConflict((oc) =>
            oc.column("userId").doUpdateSet(() => ({
              createdAt: Date.now(),
              expiresAt: datums.expiresAt,
              codeChallenge: datums.codeChallenge,
            })),
          )
          .executeTakeFirstOrThrow();

        return { sessionToken, expiration: new Date(datums.expiresAt) };
      });

      setCookie(c, "session", transactionResult.sessionToken, {
        ...COOKIE_OPTIONS,
        expires: transactionResult.expiration,
      });

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
  .patch(
    "/:userId/verify",
    guardWithUserAuth,
    validator("query", verifyResetPasswordParamsSchema.parse),
    async (c) => {
      const userId = c.get("userSession").userId!;

      const queryParams = c.req.valid("query");

      // TODO: rate limit to max 5 requests in a 5min window (by userId and not IP)

      const result = await db
        .selectFrom("passwordResetRequests")
        .select(["codeChallenge", "expiresAt as expiration"])
        .where("userId", "=", userId)
        .executeTakeFirstOrThrow();

      if (Date.now() >= result.expiration) {
        await db
          .deleteFrom("passwordResetRequests")
          .where("userId", "=", userId)
          .execute();

        throw new HTTPException(403);
      }

      const isValidCode = verifyHash(result.codeChallenge, queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      await db
        .updateTable("passwordResetRequests")
        .where("userId", "=", userId)
        .set({ validatedAt: Date.now() })
        .executeTakeFirstOrThrow();

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
  .post(
    "/:userId/reset",
    guardWithUserAuth,
    validator("json", resetPasswordBodySchema.parse),
    async (c) => {
      const userId = c.get("userSession").userId!;

      const body = c.req.valid("json");

      const result = await db
        .selectFrom("passwordResetRequests")
        .select(["codeChallenge", "expiresAt as expiration", "validatedAt"])
        .where("userId", "=", userId)
        .executeTakeFirstOrThrow();

      if (Date.now() >= result.expiration) {
        await db
          .deleteFrom("passwordResetRequests")
          .where("userId", "=", userId)
          .execute();

        throw new HTTPException(403);
      }

      if (!result.validatedAt) {
        throw new HTTPException(403);
      }

      let password = body.password.trim();

      if (password !== body.confirmPassword.trim()) {
        throw new HTTPException(400);
      }

      if (isPasswordGuessable(password)) {
        throw new HTTPException(400, { message: "Weak password" });
      }

      password = hash(password);

      const datums = await db.transaction().execute(async (trx) => {
        await trx
          .updateTable("users")
          .where("id", "=", userId)
          .set({ passwordHash: password })
          .executeTakeFirstOrThrow();

        await trx
          .deleteFrom("emailUpdateRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();

        await trx
          .deleteFrom("passwordResetRequests")
          .where("userId", "=", userId)
          .executeTakeFirst();

        await trx
          .deleteFrom("userSessions")
          .where("userId", "=", userId)
          .executeTakeFirst();

        const sessionToken = generateRandomToken();
        const expiration = Date.now() + SESSION_EXPIRATION_MS;

        await trx
          .insertInto("userSessions")
          .values({
            id: encodeSha256Hex(sessionToken),
            userId: userId,
            expiresAt: expiration,
            scope: STATIC_SESSION_SCOPE.AUTH,
          })
          .executeTakeFirstOrThrow();

        return { sessionToken, expiration };
      });

      setCookie(c, "session", datums.sessionToken, {
        ...COOKIE_OPTIONS,
        expires: new Date(datums.expiration),
      });

      return c.json(
        {
          success: true,
          error: null,
          content: null,
        } satisfies JSONResponseBase,
        201,
      );
    },
  );
