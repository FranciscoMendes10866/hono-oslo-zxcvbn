import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";

import { requestEmailVerificationQuerySchema } from "../schemas";
import { hash, verifyHash } from "../utils/common";
import {
  EMAIL_VERIFICATION_FLAGS,
  generateRandomToken,
  guardWithUserAuth,
} from "../utils/session";
import { db } from "../db";
import { emailRenderer } from "../utils/email";

export const emailVerification = new Hono()
  .post("/request", guardWithUserAuth, async (c) => {
    const userId = c.get("userSession").userId!;

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

    const emailBody = emailRenderer("EMAIL_VERIFICATION_REQUEST", {
      codeVerifier,
    });

    console.log(emailBody);

    return c.json(
      {
        success: true,
        error: null,
        content: null,
      } satisfies JSONResponseBase,
      201,
    );
  })
  .patch(
    "/request",
    guardWithUserAuth,
    validator("query", requestEmailVerificationQuerySchema.parse),
    async (c) => {
      const userId = c.get("userSession").userId!;

      const queryParams = c.req.valid("query");

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
          .execute();

        throw new HTTPException(403);
      }

      const isValidCode = verifyHash(result.codeChallenge, queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      await db.transaction().execute(async (tx) => {
        await tx
          .updateTable("users")
          .where("id", "=", userId)
          .set({ emailVerified: EMAIL_VERIFICATION_FLAGS.VERIFIED })
          .executeTakeFirstOrThrow();

        await tx
          .deleteFrom("emailVerificationRequests")
          .where("userId", "=", userId)
          .execute();
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
