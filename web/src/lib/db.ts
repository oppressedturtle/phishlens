/**
 * Prisma client singleton for PhishLens.
 *
 * Prisma 7 requires an explicit driver adapter — we use @prisma/adapter-pg
 * backed by the `pg` Pool. A module-level global keeps Next.js dev hot-reloads
 * from exhausting the connection pool by spawning a new client per change.
 */
import { Pool } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";
import { env } from "./env";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

function createPrismaClient(): PrismaClient {
  const pool = new Pool({ connectionString: env.DATABASE_URL });
  const adapter = new PrismaPg(pool);
  return new PrismaClient({
    adapter,
  } as ConstructorParameters<typeof PrismaClient>[0]);
}

export const db: PrismaClient = globalForPrisma.prisma ?? createPrismaClient();

if (env.NODE_ENV !== "production") {
  globalForPrisma.prisma = db;
}
