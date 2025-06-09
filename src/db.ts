import { CamelCasePlugin, Kysely } from "kysely";
import type { DB } from "kysely-codegen";
import { LibsqlDialect } from "@libsql/kysely-libsql";

export const db = new Kysely<DB>({
  dialect: new LibsqlDialect({
    url: "http://localhost:8080",
  }),
  plugins: [new CamelCasePlugin()],
});
