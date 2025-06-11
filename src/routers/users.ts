import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";
import { setCookie } from "hono/cookie";

import {
  signInBodySchema,
  signUpBodySchema,
  updatePasswordBodySchema,
} from "../schemas";
import {
  isPasswordGuessable,
  hash,
  encodeSha256Hex,
  normalizeEmail,
  verifyHash,
} from "../utils/common";
import {
  COOKIE_OPTIONS,
  generateRandomToken,
  SESSION_EXPIRATION_MS,
  STATIC_SESSION_SCOPE,
} from "../utils/session";
import { db } from "../db";

export const usersRouter = new Hono()
  .post("/sign-up", validator("json", signUpBodySchema.parse), async (c) => {
    const body = c.req.valid("json");

    let password = body.password.trim();
    const email = normalizeEmail(body.email);

    if (!email || password !== body.confirmPassword.trim()) {
      throw new HTTPException(400);
    }

    if (isPasswordGuessable(password)) {
      throw new HTTPException(400, { message: "Weak password" });
    }

    const result = await db
      .selectFrom("users")
      .select("id as userId")
      .where("email", "=", email)
      .executeTakeFirst();

    if (typeof result?.userId === "string") {
      throw new HTTPException(409);
    }

    password = hash(password);

    const datums = await db.transaction().execute(async (trx) => {
      const user = await trx
        .insertInto("users")
        .values({
          email,
          username: body.username?.trim(),
          passwordHash: password,
        })
        .returning("id")
        .executeTakeFirstOrThrow();

      const sessionToken = generateRandomToken();
      const expiration = Date.now() + SESSION_EXPIRATION_MS;

      await trx
        .insertInto("userSessions")
        .values({
          id: encodeSha256Hex(sessionToken),
          userId: user.id!,
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
  })
  .post("/sign-in", validator("json", signInBodySchema.parse), async (c) => {
    const body = c.req.valid("json");

    const email = normalizeEmail(body.email);
    if (!email) throw new HTTPException(500);

    const result = await db
      .selectFrom("users")
      .select(["passwordHash", "id as userId"])
      .where("email", "=", email)
      .executeTakeFirst();
    if (!result?.userId) throw new HTTPException(404);

    const isValid = verifyHash(result.passwordHash, body.password.trim());
    if (!isValid) throw new HTTPException(400);

    const sessionToken = generateRandomToken();
    const expiration = Date.now() + SESSION_EXPIRATION_MS;

    await db
      .insertInto("userSessions")
      .values({
        id: encodeSha256Hex(sessionToken),
        userId: result.userId,
        expiresAt: expiration,
        scope: STATIC_SESSION_SCOPE.AUTH,
      })
      .executeTakeFirstOrThrow();

    setCookie(c, "session", sessionToken, {
      ...COOKIE_OPTIONS,
      expires: new Date(expiration),
    });

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
    "/update-password",
    validator("json", updatePasswordBodySchema.parse),
    async (c) => {
      const body = c.req.valid("json");

      const userId = "CHANGE_ME"; // TODO: get the userId from the session itself

      // TODO: verify the session datum assigned to the http request to check if the account is verified

      const result = await db
        .selectFrom("users")
        .select("passwordHash")
        .where("id", "=", userId)
        .executeTakeFirst();
      if (!result) throw new HTTPException(404);

      const isValid = verifyHash(result.passwordHash, body.oldPassword.trim());
      if (!isValid) throw new HTTPException(400);

      let password = body.newPassword.trim();

      if (password !== body.confirmNewPassword.trim()) {
        throw new HTTPException(400);
      }

      if (isPasswordGuessable(password)) {
        throw new HTTPException(400, { message: "Weak password" });
      }

      const datums = await db.transaction().execute(async (trx) => {
        await trx
          .updateTable("users")
          .set({ passwordHash: hash(password) })
          .where("id", "=", userId)
          .executeTakeFirstOrThrow();

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
        200,
      );
    },
  );
