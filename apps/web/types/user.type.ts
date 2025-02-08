import z from 'zod';

export const UserSchema = z.object({
  id: z.number(),
  firstName: z.string(),
  lastName: z.string(),
  password: z.string(),
});

export type User = z.infer<typeof UserSchema>;

export const UsersSchema = z.array(UserSchema);

export type Users = z.infer<typeof UsersSchema>;

export const GetUserSchema = z.object({
  message: z.string(),
  data: UserSchema,
});

export type GetUser = z.infer<typeof GetUserSchema>;

export const GetUsersSchema = z.object({
  message: z.string(),
  data: UsersSchema,
});

export type GetUsers = z.infer<typeof GetUsersSchema>;
