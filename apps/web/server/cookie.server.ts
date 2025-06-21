'use server';

import { cookies } from 'next/headers';

/**
 * Set a cookie in the server-side response.
 * @param name - The name of the cookie to set.
 * @param value - The value of the cookie.
 */
export const setCookie = async ({
  name,
  value,
}: {
  name: string;
  value: string;
}) => {
  const cookie = await cookies();
  if (!cookie) return;
  cookie.set({
    name,
    value,
  });
};
