import { Hono } from "hono";
import { validator } from "hono/validator";
import { HTTPException } from "hono/http-exception";
import { setCookie } from "hono/cookie";

import { signUpBodySchema } from "../schemas";
import { isPasswordGuessable, hash, encodeSha256Hex } from "../utils/common";
import {
  COOKIE_OPTIONS,
  generateRandomToken,
  SESSION_EXPIRATION_MS,
} from "../utils/session";
import { db } from "../db";

export const usersRouter = new Hono().post(
  "/",
  validator("json", signUpBodySchema.parse),
  async (c) => {
    const body = c.req.valid("json");

    let password = body.password.trim();
    const email = body.email.trim();

    if (password !== body.confirmPassword.trim()) {
      throw new HTTPException(400);
    }

    if (isPasswordGuessable(password)) {
      throw new HTTPException(400, { message: "Weak password" });
    }

    const result = await db
      .selectFrom("users")
      .select("id")
      .where("email", "=", email)
      .executeTakeFirst();

    if (typeof result?.id === "string") {
      throw new HTTPException(409);
    }

    password = hash(password);

    const datums = await db.transaction().execute(async (trx) => {
      const user = await trx
        .insertInto("users")
        .values({
          email,
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
  },
);
