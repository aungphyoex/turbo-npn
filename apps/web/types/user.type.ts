import { z } from 'zod';

export const UserSchema = z.object({
  id: z.string().min(1),
  email: z.string().email(),
  username: z.string().min(3),
  name: z.string().min(1),
  isEmailVerified: z.boolean().default(false),
});

// TypeScript type from Zod schema
export type User = z.infer<typeof UserSchema>;

export const GetAllUsersSchema = z.object({
  data: z.array(UserSchema),
});

export type GetAllUsers = z.infer<typeof GetAllUsersSchema>;
