import { Session } from 'next-auth';
import { AdapterSession, AdapterUser } from 'next-auth/adapters';
import { JWT } from 'next-auth/jwt';

/**
 * @description Session callback function for NextAuth
 * @param session
 * @param token
 * @return Session
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
