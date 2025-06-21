import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";

import {
  requestEmailVerificationQuerySchema,
  requestEmailUpdateBodySchema,
} from "../schemas";
import { hash, normalizeEmail, verifyHash } from "../utils/common";
import {
  enforceEmailVerification,
  generateRandomToken,
  guardWithUserAuth,
} from "../utils/session";
import { db } from "../db";

export const emailUpdate = new Hono()
  .post(
    "/:userId/email-update-request",
    guardWithUserAuth,
    enforceEmailVerification,
    validator("json", requestEmailUpdateBodySchema.parse),
    async (c) => {
      const userId = c.get("userSession").userId!;

      const { newEmail } = c.req.valid("json");

      const newEmailCopy = normalizeEmail(newEmail);
      if (!newEmailCopy) throw new HTTPException(400);

      const codeVerifier = generateRandomToken(40);

      const datums = {
        userId,
        expiresAt: Date.now() + 10 * 60 * 1_000, // 10min
        codeChallenge: hash(codeVerifier),
        newEmail: newEmailCopy,
      };

      await db
        .insertInto("emailUpdateRequests")
        .values(datums)
        .onConflict((oc) =>
          oc.column("userId").doUpdateSet(() => ({
            createdAt: Date.now(),
            expiresAt: datums.expiresAt,
            codeChallenge: datums.codeChallenge,
            newEmail: datums.newEmail,
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
  .get("/:userId/email-update-request", guardWithUserAuth, async (c) => {
    const userId = c.get("userSession").userId!;

    const result = await db
      .selectFrom("emailUpdateRequests")
      .select(["expiresAt as expiration"])
      .where("userId", "=", userId)
      .executeTakeFirst();

    if (typeof result === "undefined") {
      throw new HTTPException(404);
    }

    if (Date.now() >= result.expiration) {
      await db
        .deleteFrom("emailUpdateRequests")
        .where("userId", "=", userId)
        .execute();

      throw new HTTPException(404);
    }

    return c.json(
      {
        success: true,
        error: null,
        content: result,
      } satisfies JSONResponseBase,
      200,
    );
  })
  .delete("/:userId/email-update-request", guardWithUserAuth, async (c) => {
    const userId = c.get("userSession").userId!;

    await db
      .deleteFrom("emailUpdateRequests")
      .where((eb) =>
        eb.and([eb("userId", "=", userId), eb("expiresAt", "<=", Date.now())]),
      )
      .executeTakeFirstOrThrow();

    return c.json(
      {
        success: true,
        error: null,
        content: null,
      } satisfies JSONResponseBase,
      200,
    );
  })
  .patch(
    "/:userId/validate-email-update-request",
    guardWithUserAuth,
    validator("query", requestEmailVerificationQuerySchema.parse),
    async (c) => {
      const userId = c.get("userSession").userId!;

      const queryParams = c.req.valid("query");

      const result = await db
        .selectFrom("emailUpdateRequests")
        .select(["expiresAt as expiration", "codeChallenge", "newEmail"])
        .where("userId", "=", userId)
        .executeTakeFirst();

      if (typeof result === "undefined") {
        throw new HTTPException(404);
      }

      if (Date.now() >= result.expiration) {
        await db
          .deleteFrom("emailUpdateRequests")
          .where("userId", "=", userId)
          .execute();

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
