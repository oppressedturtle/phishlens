/**
 * Zod-validated environment configuration for the PhishLens web app.
 *
 * Reads `process.env` once at module load and throws a descriptive error at
 * startup if anything required is missing or malformed. All app code must read
 * env vars from this module rather than from raw `process.env`.
 */
import { z } from "zod";

const schema = z.object({
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),
  /** Base URL of the Python FastAPI analyzer microservice. */
  ANALYZER_URL: z.string().url(),
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues
    .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
    .join("\n");
  throw new Error(
    `Invalid environment configuration:\n${issues}\n` +
      `Check your .env against .env.example.`,
  );
}

export const env = parsed.data;
export type Env = typeof env;
