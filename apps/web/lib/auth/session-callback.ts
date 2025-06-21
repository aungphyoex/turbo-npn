import { Session } from 'next-auth';
import { AdapterSession, AdapterUser } from 'next-auth/adapters';
import { JWT } from 'next-auth/jwt';

/**
 * Maps the JWT token data to the NextAuth session object.
 *
 * @param session - The current session object.
 * @param token - The JWT token containing user information.
 * @returns The updated session with detailed user data from the token.
 */
export const sessionCallback = ({
  session,
  token,
}: {
  session: {
    user: AdapterUser;
  } & AdapterSession &
    Session;
  token: JWT;
}): Session => {
  if (token) {
    const { user } = token;
    return {
      ...session,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        isEmailVerified: user.isEmailVerified,
        emailVerifiedAt: user.emailVerifiedAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        profile: user.profile,
        tokens: user.tokens,
      },
    };
  }
  return session;
};
