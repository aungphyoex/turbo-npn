import { createEnv } from '@t3-oss/env-nextjs';
import { z } from 'zod';

export const env = createEnv({
  server: {
    API_URL: z.string(),
    AUTH_SESSION_AGE: z.string().transform((value) => parseInt(value, 10)),
    AUTH_SECRET: z.string(),
  },
  client: {},
  runtimeEnv: {
    API_URL: process.env.API_URL,
    AUTH_SESSION_AGE: process.env.AUTH_SESSION_AGE,
    AUTH_SECRET: process.env.AUTH_SECRET,
  },
});
