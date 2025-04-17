import { z } from 'zod';

export const DefaultReturnSchema = z.object({
  message: z.string(),
});
