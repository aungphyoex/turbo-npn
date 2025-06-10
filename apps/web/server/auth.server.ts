'use server';

import { auth, signIn, signOut, update } from '@/auth';
import { safeAction, safeFetch } from '@/lib';
import { getDeviceInfo } from '@/lib/device';
import {
  ChangePasswordSchema,
  ConfirmEmailSchema,
  DeleteAccountSchema,
  ForgotPasswordSchema,
  GetSession,
  GetSessionSchema,
  GetSessionsSchema,
  RefreshToken,
  RefreshTokenSchema,
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
import { isRedirectError } from 'next/dist/client/components/redirect-error';
import { redirect } from 'next/navigation';

/**
 * @description Parses and sends credential-based login with device info to backend.
 * @param credentials
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
  const { data: user, tokens } = data;
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    isEmailVerified: user.isEmailVerified,
    emailVerifiedAt: user.emailVerifiedAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    profile: user.profile,
    tokens: tokens,
  };
};

/**
 * @description UI Sign-in action using credentials.
 * @schema SignInSchema
 */
export const signInWithCredentials = safeAction
  .schema(SignInSchema)
  .action(async ({ parsedInput }) => {
    try {
      await signIn('credentials', parsedInput);
    } catch (error) {
      if (error instanceof AuthError) {
        if (error.type === 'CredentialsSignin') {
          throw new Error('Invalid credentials.');
        }
        throw new Error('Something went wrong.');
      }
      if (isRedirectError(error)) {
        revalidateTag('/auth/sign-in');
        redirect('/');
      }
    }
  });

/**
 * @description UI Sign-up action with auto login.
 * @schema SignUpSchema
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
 * @description Sign out a device by session token.
 * @param token
 */
const signOutBySessionToken = async (token: string) => {
  const session = await auth();

  const [error] = await safeFetch(DefaultReturnSchema, '/auth/sign-out', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${session?.user.tokens.access_token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify({ session_token: token }),
  });

  if (error) throw error;

  revalidateTag('nest-auth-sessions');
};

/**
 * @description Sign out from current device.
 */
export const signOutCurrentDevice = safeAction.action(async () => {
  const session = await auth();
  if (!session) return;

  await signOutBySessionToken(session.user.tokens.session_token);
  await signOut({ redirect: true, redirectTo: '/' });

  return 'success';
});

/**
 * @description Sign out from a different device by session token.
 * @schema SignOutSchema
 */
export const signOutOtherDevice = safeAction
  .schema(SignOutSchema)
  .action(async ({ parsedInput }) => {
    await signOutBySessionToken(parsedInput.session_token);
    return 'success';
  });

/**
 * @description Sign out from all devices.
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
        Authorization: `Bearer ${session?.user?.tokens.access_token}`,
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
 * @description Change password for the current user.
 * @schema ChangePasswordSchema
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
          Authorization: `Bearer ${session?.user?.tokens.access_token}`,
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
 * @description Send forgot password email.
 * @schema ForgotPasswordSchema
 */
export const forgotPassword = safeAction
  .schema(ForgotPasswordSchema)
  .action(async ({ parsedInput }) => {
    const [error, data] = await safeFetch(
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
    redirect(
      `/auth/reset-password?email=${parsedInput.identifier}&message=${data.message}`,
    );
  });

/**
 * @description Reset password using token.
 * @schema ResetPasswordSchema
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
 * @description Get current session by token.
 * @schema GetSessionSchema
 */
export const getSessionById = async () => {
  const session = await auth();
  return await safeFetch(
    GetSessionSchema,
    `/auth/session/${session?.user?.tokens.session_token}`,
    {
      next: {
        tags: ['next-auth-session'],
        revalidate: 86400, // 24 hours
      },
      headers: {
        Authorization: `Bearer ${session?.user?.tokens.access_token}`,
      },
    },
  );
};

/**
 * @description Get all active sessions for the user.
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
        Authorization: `Bearer ${session?.user?.tokens.access_token}`,
      },
    },
  );

  if (error) return [];
  return data.data;
};

/**
 * @description Confirm email with token
 * @schema ConfirmEmailSchema
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
          Authorization: `Bearer ${session?.user?.tokens.access_token}`,
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
    redirect(`/`);
  });

/**
 * @description Update tokens in auth session
 * @param data
 */
const updateTokens = async (data: RefreshToken) => {
  await update({
    user: {
      tokens: {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        session_token: data.session_token,
        session_refresh_time: data.access_token_refresh_time,
      },
    },
  });
};

/**
 * @description Refresh access token with refresh token
 * @param user
 */
export const refreshAccessToken = async (user: User): Promise<unknown> => {
  const [error, data] = await safeFetch(
    RefreshTokenSchema,
    '/auth/refresh-token',
    {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${user.tokens.refresh_token}`,
        Accept: 'application/json',
      },
      cache: 'no-store',
      body: JSON.stringify({
        session_token: user.tokens.session_token,
        user_id: user.id,
      }),
    },
  );
  if (error) {
    console.log('Refresh access token error', error);
    return;
  }
  await updateTokens(data);
};

/**
 * @description Validate session if exist from server session
 */
export const validateSessionIfExist = async (): Promise<GetSession> => {
  const [error, data] = await getSessionById();
  if (error) {
    console.log('Validate session error', error);
    await signOut({
      redirect: false,
    });
  }
  console.log('Validate session success');
  return data;
};

/**
 * @description Delete account
 * @schema DeleteAccountSchema
 * @param parsedInput
 * @returns Promise<MessageResponse>
 */
export const deleteAccount = safeAction
  .schema(DeleteAccountSchema)
  .action(async ({ parsedInput }) => {
    const session = await auth();
    const [error] = await safeFetch(
      DefaultReturnSchema,
      '/auth/delete-account',
      {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.user?.tokens.access_token}`,
          Accept: 'application/json',
        },
        cache: 'no-store',
        body: JSON.stringify({
          user_id: session?.user.id,
          password: parsedInput.password,
        }),
      },
    );
    if (error) throw new Error(error);
    redirect('/auth/sign-in');
  });
