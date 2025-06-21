import { z } from 'zod';

/**
 * Schema for a default API response containing a message.
 */
export const DefaultReturnSchema = z.object({
  message: z.string(),
});
