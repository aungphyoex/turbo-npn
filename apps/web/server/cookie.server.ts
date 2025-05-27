'use server';

import { cookies } from 'next/headers';

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
