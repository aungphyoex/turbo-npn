import { env } from '@/lib';
import { authorizeSignIn } from '@/server/auth.server';
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
export const {
  handlers,
  signIn,
  signOut,
  auth,
  unstable_update: update,
} = NextAuth({
  providers: [
    Credentials({
      name: 'Credentials',
      credentials: {
        identifier: { label: 'Identifier', type: 'string' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        return await authorizeSignIn({
          identifier: credentials.identifier as string,
          password: credentials.password as string,
        });
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger, session }) {
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
    },
    async session({ session, token }) {
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
    },
    async authorized({ request, auth }) {
      const isAuth = !!auth?.user;
      const isVerifiedUser = !!auth?.user.isEmailVerified;
      const { nextUrl } = request;
      const { pathname } = nextUrl;

      if (!isAuth) {
        if (
          pathname === '/' ||
          pathname.startsWith('/p') ||
          pathname.startsWith('/auth/confirm-email')
        ) {
          return Response.redirect(new URL('/auth/sign-in', nextUrl));
        }
      }

      if (isAuth) {
        if (!isVerifiedUser) {
          const isAlreadyOnConfirmPage = pathname.startsWith(
            '/auth/confirm-email',
          );
          if (!isAlreadyOnConfirmPage) {
            return Response.redirect(new URL('/auth/confirm-email', nextUrl));
          }
        }
        if (
          pathname.startsWith('/auth/sign') ||
          (pathname.startsWith('/auth/confirm-email') && isVerifiedUser)
        ) {
          return Response.redirect(new URL('/', nextUrl));
        }
      }

      return true;
    },
  },
  session: {
    strategy: 'jwt',
    maxAge: env.AUTH_SESSION_AGE,
    updateAge: 86400 * 5, //5 days,
  },
  secret: env.AUTH_SECRET,
  useSecureCookies: env.NODE_ENV === 'production',
  redirectProxyUrl: env.AUTH_URL,
  pages: {
    signIn: '/auth/sign-in',
    signOut: '/auth/sign-out',
    error: '/auth/sign-in',
    verifyRequest: '/auth/confirm-email',
    newUser: '/auth/sign-up',
  },
});
