import 'next-auth';
import { User } from 'next-auth';

declare module 'next-auth' {
  /**
   * The shape of the user object returned in the OAuth providers' `[username]` callback,
   * or the second parameter of the `session` callback, when using a database.
   */
  interface User {
    id: string;
    name: string;
    email: string;
    username: string;
    isEmailVerified: boolean;
    auth: {
      access_token: string;
      refresh_token: string;
      session_token: string;
      session_refresh_time: Date;
    };
  }

  /**
   * Returned by `useSession`, `auth`, contains information about the active session.
   */
  interface Session {
    user: User;
  }
}

// The `JWT` interface can be found in the `next-auth/jwt` submodule
import 'next-auth/jwt';

declare module 'next-auth/jwt' {
  /** Returned by the `jwt` callback and `auth`, when using JWT sessions */
  interface JWT {
    user: User;
  }
}
