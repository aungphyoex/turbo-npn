// export { auth as middleware } from '@/auth';

import {
  refreshAccessToken,
  validateSessionIfExist,
} from '@/server/auth.server';
import { auth } from './auth';

export default auth(async (req) => {
  /**
   * @description Refresh Access Token if needed before each request to the protected routes in the application.
   * @param req
   */
  if (req.auth && req.auth.user) {
    const user = req.auth.user;
    const session_refresh_time = new Date(
      user.tokens.session_refresh_time,
    ).getTime();
    const now = new Date().getTime();
    if (session_refresh_time <= now) {
      console.log('========== Refresh Access Token Started =========');
      await refreshAccessToken(user);
      console.log('========== Refresh Access Token Ended =========');
    }
  }
  if (req.auth && req.auth.user) {
    console.log(`========== Validate Server Session Started =========`);
    await validateSessionIfExist();
    console.log('========== Validate Server Session Ended =========');
  }
});

export const config = {
  // https://nextjs.org/docs/app/building-your-application/routing/middleware#matcher
  matcher: ['/((?!api|_next/static|_next/image|.*\\.png$).*)'],
};
