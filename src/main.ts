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
import { generateCookieDefaults, generateRandomToken } from "./utils/session";

const COOKIE_OPTIONS = Object.freeze(generateCookieDefaults());

const app = new Hono()
  .basePath("/api")
  .use(
    cors({
      credentials: true,
      origin: process.env.FRONTEND_DOMAIN_URL || "*",
    }),
  )
  .post("/users", validator("json", signUpBodySchema.parse), (c) => {
    const body = c.req.valid("json");

    let password = body.password.trim();

    if (password !== body.confirmPassword.trim()) {
      throw new HTTPException(400);
    }

    if (isPasswordGuessable(password)) {
      throw new HTTPException(400, { message: "Weak password" });
    }

    // TODO: check if account/email is taken

    password = hash(password);

    const sessionToken = generateRandomToken();
    const sessionId = encodeSha256Hex(sessionToken);

    // TODO: insert datum into db

    setCookie(c, "session", sessionToken, {
      ...COOKIE_OPTIONS,
      expires: new Date(), // TODO: replace this
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
    (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself

      // TODO: rate limit to max 1 request in a 10min window (by userId and not IP)

      // TODO: check if user exists and include existing email verification request datum (1-1 rel)

      // TODO: check expiration, on expired invalidate row datum

      const codeVerifier = generateRandomToken(40);

      const datum = {
        userId,
        expiresAt: new Date(), // TODO: replace this (current time plus 10min)
        codeChallenge: hash(codeVerifier),
      };

      // TODO: insert datum into db (1-1 rel)

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
    (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const queryParams = c.req.valid("query");

      // TODO: rate limit to max 5 requests in a 5min window (by userId and not IP)

      // TODO: check if user exists and include existing email verification request datum (1-1 rel)

      // TODO: check expiration, on fail invalidate row datum

      const isValidCode = verifyHash("CHANGE_ME", queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      // TODO: invalidate row datum

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
    (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const { newEmail } = c.req.valid("json");

      // TODO: rate limit to max 1 request in a 10min window (by userId and not IP)

      // TODO: check if user exists and include existing email update request datum (1-1 rel)

      // TODO: check if the user's current email is verified

      // TODO: check expiration, on expired invalidate row datum

      // TODO: check if the user's current email is the same as the 'newEmail'

      // TODO: check if the 'newEmail' is already taken

      const codeVerifier = generateRandomToken(40);

      const datum = {
        userId,
        expiresAt: new Date(), // TODO: replace this (current time plus 10min)
        codeChallenge: hash(codeVerifier),
        email: newEmail,
      };

      // TODO: insert datum into db (1-1 rel)

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
    (c) => {
      const { userId } = c.req.valid("param"); // Doubt: maybe it is better to get the userId from the session itself
      const queryParams = c.req.valid("query");

      // TODO: rate limit to max 5 requests in a 5min window (by userId and not IP)

      // TODO: check if user exists and include existing email update request datum (1-1 rel)

      // TODO: check expiration, on fail invalidate row datum

      const isValidCode = verifyHash("CHANGE_ME", queryParams.code);
      if (!isValidCode) throw new HTTPException(400);

      // TODO: update user email with the email update request datum 'new email'

      // TODO: invalidate email update request row

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
