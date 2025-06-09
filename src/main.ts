import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";

import { usersRouter } from "./routers/users";
import { emailVerification } from "./routers/email-verification";
import { emailUpdate } from "./routers/email-update";

const app = new Hono()
  .basePath("/api/auth")
  .use(
    cors({
      credentials: true,
      origin: process.env.FRONTEND_DOMAIN_URL || "*",
    }),
  )
  .route("/users", usersRouter)
  .route("/email-verification", emailVerification)
  .route("/email-update", emailUpdate);

serve({ port: 3333, fetch: app.fetch });
