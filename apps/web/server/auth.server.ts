'use server';

import { auth, signIn, signOut, update } from '@/auth';
import { safeAction, safeFetch } from '@/lib';
import { getDeviceInfo } from '@/lib/device';
import {
  ChangePasswordSchema,
  ConfirmEmailSchema,
  ForgotPasswordSchema,
  GetSessionSchema,
  GetSessionsSchema,
  ResetPasswordSchema,
  Session,
  SignIn,
  SignInDataSchema,
  SignInSchema,
  SignOutSchema,
  SignUpSchema,
} from '@/types/auth.type';
import { DefaultReturnSchema } from '@/types/default.type';
import { AuthError, User } from 'next-auth';
import { revalidateTag } from 'next/cache';
import { redirect } from 'next/navigation';

/**
 * Parses and sends credential-based login with device info to backend.
 */
export const authorizeSignIn = async (
  credentials: SignIn,
): Promise<null | User> => {
  const deviceInfo = await getDeviceInfo();

  const [error, data] = await safeFetch(SignInDataSchema, '/auth/sign-in', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    cache: 'no-store',
    body: JSON.stringify({
      ...credentials,
      ...deviceInfo,
    }),
  });

  if (error) return null;

  return {
    id: data.data.id,
    name: data.data.name,
    email: data.data.email,
    username: data.data.username,
    isEmailVerified: data.data.isEmailVerified,
    auth: {
      access_token: data.tokens.access_token,
      refresh_token: data.tokens.refresh_token,
      session_token: data.tokens.session_token,
    },
  };
};

/**
 * UI Sign-in action using credentials.
 */
export const signInWithCredentials = safeAction
  .schema(SignInSchema)
  .action(async ({ parsedInput }) => {
    try {
      await signIn('credentials', {
        ...parsedInput,
        redirect: true,
        redirectTo: '/profile',
      });
    } catch (error) {
      if (error instanceof AuthError) {
        if (error.type === 'CredentialsSignin') {
          throw new Error('Invalid credentials.');
        }
        throw new Error('Something went wrong.');
      }
    }
  });

/**
 * UI Sign-up action with auto login.
 */
export const signUpWithCredentials = safeAction
  .schema(SignUpSchema)
  .action(async ({ parsedInput }) => {
    const [error] = await safeFetch(DefaultReturnSchema, '/auth/sign-up', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(parsedInput),
    });

    if (error) throw error;

    await signIn('credentials', {
      identifier: parsedInput.email,
      password: parsedInput.password,
      redirect: true,
      redirectTo: '/auth/confirm-email',
    });
  });

/**
 * Sign out a device by session token.
 */
const signOutBySessionToken = async (token: string) => {
  const session = await auth();

  const [error] = await safeFetch(DefaultReturnSchema, '/auth/sign-out', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${session?.user.auth.access_token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify({ session_token: token }),
  });

  if (error) throw error;

  revalidateTag('nest-auth-sessions');
};

/**
 * Sign out from current device.
 */
export const signOutCurrentDevice = safeAction.action(async () => {
  const session = await auth();
  if (!session) return;

  await signOutBySessionToken(session.user.auth.session_token);
  await signOut({ redirect: true, redirectTo: '/' });

  return 'success';
});

/**
 * Sign out from a different device by session token.
 */
export const signOutOtherDevice = safeAction
  .schema(SignOutSchema)
  .action(async ({ parsedInput }) => {
    await signOutBySessionToken(parsedInput.session_token);
    return 'success';
  });

/**
 * Sign out from all devices.
 */
export const signOutAllDevice = safeAction.action(async () => {
  const session = await auth();

  const [error] = await safeFetch(
    DefaultReturnSchema,
    '/auth/sign-out-allDevices',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session?.user.auth.access_token}`,
        Accept: 'application/json',
      },
      body: JSON.stringify({ userId: session?.user.id }),
    },
  );

  if (!error) {
    revalidateTag('nest-auth-sessions');
    await signOut({ redirect: true, redirectTo: '/' });
  }
});

/**
 * Change password for the current user.
 */
export const changePassword = safeAction
  .schema(ChangePasswordSchema)
  .action(async ({ parsedInput }) => {
    const session = await auth();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { confirmNewPassword, ...payload } = parsedInput;

    const [error, resultData] = await safeFetch(
      DefaultReturnSchema,
      '/auth/change-password',
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.user.auth.access_token}`,
          Accept: 'application/json',
        },
        body: JSON.stringify({
          identifier: session?.user.email,
          ...payload,
        }),
      },
    );

    if (error) throw new Error(error);
    return resultData;
  });

/**
 * Send forgot password email.
 */
export const forgotPassword = safeAction
  .schema(ForgotPasswordSchema)
  .action(async ({ parsedInput }) => {
    const [error] = await safeFetch(
      DefaultReturnSchema,
      '/auth/forgot-password',
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        cache: 'no-store',
        body: JSON.stringify(parsedInput),
      },
    );
    if (error) throw error;
    redirect('/auth/reset-password');
  });

/**
 * Reset password using token.
 */
export const resetPassword = safeAction
  .schema(ResetPasswordSchema)
  .action(async ({ parsedInput }) => {
    const [error] = await safeFetch(
      DefaultReturnSchema,
      '/auth/reset-password',
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        cache: 'no-store',
        body: JSON.stringify(parsedInput),
      },
    );
    if (error) throw error;
    redirect('/auth/sign-in');
  });

/**
 * Get current session by token.
 */
export const getSessionById = async () => {
  const session = await auth();
  return await safeFetch(
    GetSessionSchema,
    `/auth/session/${session?.user.auth.session_token}`,
    {
      next: {
        tags: ['next-auth-session'],
        revalidate: 86400, // 24 hours
      },
      headers: {
        Authorization: `Bearer ${session?.user.auth.access_token}`,
      },
    },
  );
};

/**
 * Get all active sessions for the user.
 */
export const getAuthSessions = async (): Promise<Session[]> => {
  const session = await auth();

  const [error, data] = await safeFetch(
    GetSessionsSchema,
    `/auth/sessions/${session?.user.id}`,
    {
      next: {
        tags: ['nest-auth-sessions'],
        revalidate: 3600, // 1 hour
      },
      headers: {
        Authorization: `Bearer ${session?.user?.auth.access_token}`,
      },
    },
  );

  if (error) return [];
  return data.data;
};

/**
 * Confirm email with token
 */
export const confirmEmail = safeAction
  .schema(ConfirmEmailSchema)
  .action(async ({ parsedInput }) => {
    const session = await auth();
    const [error] = await safeFetch(
      DefaultReturnSchema,
      '/auth/confirm-email',
      {
        method: 'PATCH',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${session?.user?.auth.access_token}`,
        },
        body: JSON.stringify(parsedInput),
      },
    );
    if (error) throw new Error(error);
    await update({
      user: {
        isEmailVerified: true,
      },
    });
    redirect('/profile');
  });
