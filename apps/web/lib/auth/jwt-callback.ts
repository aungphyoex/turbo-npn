import { triggerType } from '@/lib/auth/index';
import { Session, User } from 'next-auth';
import { AdapterUser } from 'next-auth/adapters';
import { JWT } from 'next-auth/jwt';

/**
 * @description JWT callback function for NextAuth
 * @param token
 * @param user
 * @param trigger
 * @param session
 * @return JWT
 */
export const jwtCallback = ({
  token,
  user,
  trigger,
  session,
}: {
  token: JWT;
  user: User | AdapterUser;
  trigger: triggerType;
  session: Session;
}): JWT => {
  if (trigger === 'update') {
    return {
      ...token,
      user: {
        ...token.user,
        ...session.user,
      },
    };
  }
  if (trigger === 'signIn') {
    if (user) {
      return {
        ...token,
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
  }
  return token;
};
