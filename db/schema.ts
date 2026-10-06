import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
export const vault = sqliteTable("vault", {
  id: integer("id").primaryKey(),
  envelope: text("envelope").notNull(),
  writeHash: text("write_hash").notNull(),
  revision: integer("revision").notNull().default(1),
});
