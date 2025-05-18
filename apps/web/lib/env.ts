import { createEnv } from '@t3-oss/env-nextjs';
import { z } from 'zod';

export const env = createEnv({
  server: {
    API_URL: z.string().url(),
    AUTH_SESSION_AGE: z.coerce.number(),
    AUTH_SECRET: z.string(),
    NODE_ENV: z.string(),
    AUTH_URL: z.string().url(),
  },
  client: {},
  runtimeEnv: {
    API_URL: process.env.API_URL,
    AUTH_SESSION_AGE: process.env.AUTH_SESSION_AGE,
    AUTH_SECRET: process.env.AUTH_SECRET,
    NODE_ENV: process.env.NODE_ENV,
    AUTH_URL: process.env.AUTH_URL,
  },
});
