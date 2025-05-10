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
  pages: {
    signIn: '/auth/sign-in',
  },
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
              },
            },
          };
        }
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        return {
          ...session,
          user: {
            id: token.user.id,
            name: token.user.name,
            email: token.user.email,
            image: token.user.image,
            username: token.user.username,
            isEmailVerified: token.user.isEmailVerified,
            auth: {
              access_token: token.user.auth.access_token,
              refresh_token: token.user.auth.refresh_token,
              session_token: token.user.auth.session_token,
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
        if (pathname.startsWith('/profile')) {
          return Response.redirect(new URL('/', nextUrl));
        }
      }
      if (isAuth) {
        if (pathname.startsWith('/auth/sign')) {
          return Response.redirect(new URL('/profile', nextUrl));
        }
        if (pathname.startsWith('/auth/confirm-email') && isVerifiedUser) {
          return Response.redirect(new URL('/profile', nextUrl));
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
});
