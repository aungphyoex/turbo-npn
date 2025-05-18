import { env, isAuthorized, jwtCallback, sessionCallback } from '@/lib';
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
  /**
   * @description Authentication providers
   */
  providers: [
    Credentials({
      name: 'Credentials',
      credentials: {
        identifier: { label: 'Identifier', type: 'string' },
        password: { label: 'Password', type: 'password' },
      },
      /**
       * @description Authorization logic for credentials provider
       * @param credentials - Credentials object (contains identifier and password)
       */
      async authorize(credentials) {
        return await authorizeSignIn({
          identifier: credentials.identifier as string,
          password: credentials.password as string,
        });
      },
    }),
  ],

  /**
   * @description Callback functions for token and session management
   */
  callbacks: {
    /**
     * @description Custom JWT callback to extend the token with additional fields
     * @param token - Current JWT token
     * @param user - User object (only available on sign-in)
     * @param trigger - Trigger type (e.g., "signIn", "update")
     * @param session - Current session object (on update)
     */
    async jwt({ token, user, trigger, session }) {
      return jwtCallback({ token, user, trigger, session });
    },

    /**
     * @description Custom session callback to include token data in the session
     * @param session - Current session
     * @param token - Current JWT token
     */
    async session({ session, token }) {
      return sessionCallback({ session, token });
    },

    /**
     * @description Authorization logic for middleware
     * @param request - Request object
     * @param auth - Auth object (contains token/session info)
     */
    async authorized({ request, auth }) {
      return isAuthorized({ request, auth });
    },
  },

  /**
   * @description JWT session strategy settings
   */
  session: {
    strategy: 'jwt',
    maxAge: env.AUTH_SESSION_AGE, // Total session lifetime (in seconds)
    updateAge: 86400 * 5, // Revalidate session every 5 days
  },

  /**
   * @description Secret used to sign the JWT and encrypt session data
   */
  secret: env.AUTH_SECRET,

  /**
   * @description Use secure cookies in production only
   */
  useSecureCookies: env.NODE_ENV === 'production',

  /**
   * @description Required when behind a proxy (e.g., Vercel or Cloudflare)
   */
  redirectProxyUrl: env.AUTH_URL,

  /**
   * @description Custom pages for authentication flow
   */
  pages: {
    signIn: '/auth/sign-in',
    signOut: '/auth/sign-out',
    error: '/auth/sign-in',
    verifyRequest: '/auth/confirm-email',
    newUser: '/auth/sign-up',
  },
});
