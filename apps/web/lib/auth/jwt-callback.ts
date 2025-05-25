import { triggerType } from '@/lib/auth';
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
  }
  return token;
};
