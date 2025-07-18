import { Hono } from "hono";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import { serve } from "@hono/node-server";

import { sessionMiddleware } from "./utils/session";
import { usersRouter } from "./routers/users";
import { emailVerification } from "./routers/email-verification";
import { emailUpdate } from "./routers/email-update";
import { passwordReset } from "./routers/password-reset";

const app = new Hono()
  .basePath("/api/auth")
  .use(
    cors({
      credentials: true,
      origin: process.env.FRONTEND_DOMAIN_URL || "*",
    }),
  )
  .use(sessionMiddleware)
  .onError((exception, c) => {
    console.error(exception);
    if (exception instanceof HTTPException) {
      return c.json(
        {
          success: false,
          error: exception.message,
          content: new Date().toISOString(),
        } satisfies JSONResponseBase<string>,
        exception.status,
      );
    }
    return c.json(
      {
        success: false,
        error: "Internal Server Error",
        content: new Date().toISOString(),
      } satisfies JSONResponseBase<string>,
      500,
    );
  })
  .route("/users", usersRouter)
  .route("/email-verification", emailVerification)
  .route("/email-update", emailUpdate)
  .route("/password-reset", passwordReset);

serve({ port: 3333, fetch: app.fetch });
