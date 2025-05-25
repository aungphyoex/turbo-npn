import { z } from 'zod';

export const UserSchema = z.object({
  id: z.string().min(1),
  email: z.string().email(),
  username: z.string().min(1),
  isEmailVerified: z.boolean(),
  emailVerifiedAt: z.coerce.date().nullish(),
  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date(),
  profile: z.object({
    name: z.string().min(1),
    gender: z.string().min(1),
    phoneNumber: z.string().nullish(),
    profilePicture: z.string().nullish(),
    dateOfBirth: z.coerce.date().nullish(),
    address: z.string().nullish(),
  }),
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
