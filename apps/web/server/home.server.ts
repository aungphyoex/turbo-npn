'use server';

import { safeFetch } from '@/lib/safeFetch';
import { GetAllUsers, GetAllUsersSchema } from '@/types/user.type';

export const getAllUsers = async (): Promise<GetAllUsers> => {
  const [isError, data] = await safeFetch(GetAllUsersSchema, '/users', {
    cache: 'no-store',
  });
  if (isError)
    return {
      data: [],
    };
  return data;
};
