import { z } from 'zod';

export const UserSchema = z.object({
  id: z.string().min(1),
  email: z.string().email(),
  username: z.string(),
  name: z.string().min(1),
  isEmailVerified: z.boolean().default(false),
});
export type User = z.infer<typeof UserSchema>;

export const GetUserSchema = z.object({
  data: UserSchema,
});
export type GetUser = z.infer<typeof GetUserSchema>;

export const GetAllUsersSchema = z.object({
  data: z.array(UserSchema),
});

export type GetAllUsers = z.infer<typeof GetAllUsersSchema>;
