import { z } from 'zod';

/**
 * Zod schema for validating and typing environment variables.
 */
export const EnvSchema = z.object({
  HOST: z.string(),
  NODE_ENV: z
    .enum(['development', 'production', 'test', 'provision'])
    .default('development'),
  PORT: z.coerce.number(),
  ALLOW_CORS_URL: z.string().url(),
  ACCESS_TOKEN_SECRET: z.string().min(10).max(128),
  ACCESS_TOKEN_EXPIRATION: z.string().min(1).max(60),
  REFRESH_TOKEN_SECRET: z.string().min(10).max(128),
  REFRESH_TOKEN_EXPIRATION: z.string().min(1).max(365),
  DB_HOST: z.string(),
  DB_PORT: z.string(),
  DB_USERNAME: z.string(),
  DB_PASSWORD: z.string(),
  DB_NAME: z.string(),
  DB_SSL: z.string().transform((value) => value === 'true'),
  MAIL_HOST: z.string(),
  MAIL_USERNAME: z.string(),
  MAIL_PASSWORD: z.string(),
  FILE_SYSTEM: z.enum(['s3', 'public']),
  FILE_MAX_SIZE: z.coerce.number().default(20971520),
  AWS_REGION: z.string().default(''),
  AWS_ACCESS_KEY_ID: z.string().default(''),
  AWS_SECRET_ACCESS_KEY: z.string().default(''),
  AWS_S3_BUCKET_NAME: z.string().default(''),
  AWS_S3_ENDPOINT: z.string().default(''),
});

/**
 * Type representing validated environment variables.
 */
export type Env = z.infer<typeof EnvSchema>;

/**
 * Validates a configuration object against the environment schema.
 *
 * @param {Record<string, unknown>} config - The configuration object to validate.
 * @returns {Env} The validated and typed environment variables.
 * @throws {Error} If validation fails.
 */
export const validateEnv = (config: Record<string, unknown>): Env => {
  const validate = EnvSchema.safeParse(config);
  if (!validate.success) {
    throw new Error(validate.error.message);
  }
  return validate.data;
};
