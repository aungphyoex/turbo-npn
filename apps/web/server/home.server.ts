'use server';

import { safeFetch } from '@/lib';
import { GetUsersSchema, User } from '@/types/user.type';

export const getUsers = async (): Promise<User[]> => {
  const [error, data] = await safeFetch(GetUsersSchema, '/users', {
    cache: 'no-store',
  });
  if (error) return [];
  return data.data;
};
