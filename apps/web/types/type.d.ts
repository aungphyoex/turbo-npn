import 'next-auth';
import { User } from 'next-auth';

/**
 * Module augmentation for next-auth to extend User, Session, and JWT interfaces.
 */
declare module 'next-auth' {
  /**
   * The shape of the user object returned in the OAuth providers' `[username]` callback,
   * or the second parameter of the `session` callback, when using a database.
   *
   * @interface User
   * @property {string} id - Unique identifier for the user.
   * @property {string} email - User's email address.
   * @property {string} username - User's username.
   * @property {boolean} isEmailVerified - Indicates if the user's email is verified.
   * @property {Date | null} [emailVerifiedAt] - Date when the email was verified, if applicable.
   * @property {Date} createdAt - Date when the user was created.
   * @property {Date} updatedAt - Date when the user was last updated.
   * @property {Object} profile - User's profile information.
   * @property {string} profile.name - Name of the user.
   * @property {string} profile.gender - Gender of the user.
   * @property {string | null} [profile.phoneNumber] - Optional phone number.
   * @property {string | null} [profile.profilePicture] - Optional profile picture URL.
   * @property {Date | null} [profile.dateOfBirth] - Optional date of birth.
   * @property {string | null} [profile.address] - Optional address.
   * @property {Object} tokens - Authentication tokens.
   * @property {string} tokens.access_token - Access token.
   * @property {string} tokens.refresh_token - Refresh token.
   * @property {string} tokens.session_token - Session token.
   * @property {Date} tokens.session_refresh_time - Session refresh time.
   */
  interface User {
    id: string;
    email: string;
    username: string;
    isEmailVerified: boolean;
    emailVerifiedAt?: Date | null;
    createdAt: Date;
    updatedAt: Date;
    profile: {
      name: string;
      gender: string;
      phoneNumber?: string | null;
      profilePicture?: string | null;
      dateOfBirth?: Date | null;
      address?: string | null;
    };
    tokens: {
      access_token: string;
      refresh_token: string;
      session_token: string;
      session_refresh_time: Date;
    };
  }

  /**
   * Returned by `useSession`, `auth`, contains information about the active session.
   *
   * @interface Session
   * @property {User} user - The authenticated user.
   */
  interface Session {
    user: User;
  }
}

// The `JWT` interface can be found in the `next-auth/jwt` submodule
import 'next-auth/jwt';

/**
 * Module augmentation for next-auth/jwt to extend JWT interface.
 *
 * @interface JWT
 * @property {User} user - The user object stored in the JWT.
 */
declare module 'next-auth/jwt' {
  interface JWT {
    user: User;
  }
}
