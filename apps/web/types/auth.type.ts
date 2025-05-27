import { UserSchema } from '@/types/user.type';
import { z } from 'zod';

/**
 * Password schema for validation
 */
const passWordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .refine((val) => /[A-Z]/.test(val), {
    message: 'Password must contain at least one uppercase letter',
  })
  .refine((val) => /\d/.test(val), {
    message: 'Password must contain at least one number',
  })
  .refine((val) => /[!@#$%^&*(),.?":{}|<>]/.test(val), {
    message: 'Password must contain at least one special character',
  });
/**
 * Schema for user sign-up
 */
export const SignUpSchema = z.object({
  email: z.string().email(), // Validates a proper email format
  password: passWordSchema, // Validates non-empty string for password
});

/**
 * Schema for user sign-in using either email or username
 */
export const SignInSchema = z.object({
  identifier: z.string().min(1, {
    message: 'Email or Username is required!',
  }),
  password: z.string().min(1, {
    message: 'Password is required!',
  }),
});

export type SignIn = z.infer<typeof SignInSchema>;
/**
 * Schema for sign-in response data, including user info and tokens
 */
export const SignInDataSchema = z.object({
  data: UserSchema, // User data according to UserSchema
  tokens: z.object({
    refresh_token: z.string(), // Token for refreshing access
    access_token: z.string(), // Access token for authentication
    session_token: z.string(), // Token for identifying user session
    session_refresh_time: z.coerce.date(),
  }),
});

/**
 * Schema representing a single session
 */
export const SessionSchema = z.object({
  id: z.string().min(1), // Session ID
  createdAt: z.coerce.date(), // Coerces string to Date object
  updatedAt: z.coerce.date(),
  ip: z.string().min(1), // IP address of the session
  browser: z.string().min(1), // Browser info
  device_os: z.string().min(1), // Device operating system
  device_type: z.string().min(1), // Device type (e.g., desktop, mobile)
  device_name: z.string().min(1), // Device name
  location: z.string().min(1), // Geographical location
  refresh_token: z.string(), // Associated refresh token
  user_id: z.string(), // Associated user ID
});

export type Session = z.infer<typeof SessionSchema>; // Type for session

/**
 * Schema for getting a single session response
 */
export const GetSessionSchema = z.object({
  data: SessionSchema,
});

export type GetSession = z.infer<typeof GetSessionSchema>;
/**
 * Schema for getting multiple sessions
 */
export const GetSessionsSchema = z.object({
  data: z.array(SessionSchema),
});

/**
 * Schema for signing out a session using the session token
 */
export const SignOutSchema = z.object({
  session_token: z.string(),
});

/**
 * Schema for changing password
 */
export const ChangePasswordSchema = z
  .object({
    password: passWordSchema, // Current password
    newPassword: passWordSchema, // New password
    confirmNewPassword: passWordSchema, // Confirmation of new password
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: "Passwords don't match",
    path: ['confirmNewPassword'], // GlobalError path for mismatch
  })
  .refine((data) => data.password !== data.newPassword, {
    message: "Don't use same password!",
    path: ['newPassword'],
  });

/**
 * Schema for initiating password reset (forgot password)
 */
export const ForgotPasswordSchema = z.object({
  identifier: z.string(), // Email or username
});

/**
 * Schema for resetting password using a token
 */
export const ResetPasswordSchema = z.object({
  identifier: z.string(), // Email or username
  resetToken: z.string().min(6).max(6), // 6-character reset token
  newPassword: z.string(), // New password
});

/**
 * Schema for confirm email using a token
 */
export const ConfirmEmailSchema = z.object({
  email: z.string().email(),
  token: z.string().min(6).max(6),
});

/**
 * Refresh access token with refresh token
 */
export const RefreshTokenSchema = z.object({
  refresh_token: z.string(),
  access_token: z.string(),
  session_token: z.string(),
  access_token_refresh_time: z.coerce.date(),
});

export type RefreshToken = z.infer<typeof RefreshTokenSchema>;
