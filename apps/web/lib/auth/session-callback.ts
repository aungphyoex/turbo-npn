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
        name: user.name,
        email: user.email,
        image: user.image,
        username: user.username,
        isEmailVerified: user.isEmailVerified,
        auth: {
          access_token: user.auth.access_token,
          refresh_token: user.auth.refresh_token,
          session_token: user.auth.session_token,
          session_refresh_time: user.auth.session_refresh_time,
        },
      },
    };
  }
  return session;
};
