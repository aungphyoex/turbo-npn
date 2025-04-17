import { UserSchema } from '@/types/user.type';
import { z } from 'zod';

/**
 * Schema for user sign-up
 */
export const SignUpSchema = z.object({
  email: z.string().email(), // Validates a proper email format
  password: z.string(), // Validates non-empty string for password
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

/**
 * Schema for sign-in response data, including user info and tokens
 */
export const SignInDataSchema = z.object({
  data: UserSchema, // User data according to UserSchema
  tokens: z.object({
    refresh_token: z.string(), // Token for refreshing access
    access_token: z.string(), // Access token for authentication
    session_token: z.string(), // Token for identifying user session
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
    password: z.string(), // Current password
    newPassword: z.string(), // New password
    confirmNewPassword: z.string(), // Confirmation of new password
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: "Passwords don't match",
    path: ['confirmNewPassword'], // Error path for mismatch
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
