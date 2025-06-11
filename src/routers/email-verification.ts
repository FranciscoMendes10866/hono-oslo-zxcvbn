import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";

import {
  requestEmailVerificationParamsSchema,
  requestEmailVerificationQuerySchema,
} from "../schemas";
import { hash, verifyHash } from "../utils/common";
import { generateRandomToken } from "../utils/session";
import { db } from "../db";

export const emailVerification = new Hono()
  .post(
    "/:userId/request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // TODO: maybe it is better to get the userId from the session itself

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
  .patch(
    "/:userId/request",
    validator("param", requestEmailVerificationParamsSchema.parse),
    validator("query", requestEmailVerificationQuerySchema.parse),
    async (c) => {
      const { userId } = c.req.valid("param"); // TODO: maybe it is better to get the userId from the session itself
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
          .execute();

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
