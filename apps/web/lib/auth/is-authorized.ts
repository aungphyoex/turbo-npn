import { Session } from 'next-auth';
import { NextRequest } from 'next/server';

/**
 * @description Check if the user is authorized to access the resource
 * @param request
 * @param auth
 * @return boolean
 */

export const isAuthorized = ({
  request,
  auth,
}: {
  request: NextRequest;
  auth: Session | null;
}) => {
  const isAuth = !!auth?.user;
  const isVerifiedUser = !!auth?.user.isEmailVerified;
  const { nextUrl } = request;
  const { pathname } = nextUrl;

  if (pathname.startsWith('/assets') || pathname.startsWith('/favicon.ico')) {
    return true;
  }
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
      const isAlreadyOnConfirmPage = pathname.startsWith('/auth/confirm-email');
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
};
